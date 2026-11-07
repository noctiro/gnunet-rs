//! Real partial Unix input and source-refusal ownership, independent of C hosting.
#![expect(
    clippy::panic_in_result_fn,
    reason = "Actual socket ownership assertions"
)]
use gnunet_crypto::{EddsaPrivateKey, Entropy};
use gnunet_service_runtime::connection::Connection;
use gnunet_transport::{Engine, Limits, PeerId, Signer, application::Preference};
use gnunet_transport_host::{
    AddressStore, Server,
    discovery::{AddressSource, Visit, VisitControl},
};
use gnunet_types::Error;
use std::{cell::Cell, num::NonZeroUsize, rc::Rc, time::Duration};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::UnixStream,
};
struct Key(EddsaPrivateKey);
impl Signer for Key {
    fn identity(&self) -> PeerId {
        PeerId(*self.0.public_key().as_bytes())
    }
    fn sign_validation(&mut self, r: &[u8; 48]) -> Result<[u8; 64], Error> {
        Ok(*self.0.sign(35, r)?.as_bytes())
    }
}
struct Random;
impl Entropy for Random {
    fn fill(&mut self, b: &mut [u8]) -> Result<(), Error> {
        b.fill(7);
        Ok(())
    }
}
struct Store;
impl AddressStore for Store {
    fn validated(&mut self, _: PeerId, _: &[u8], _: u64) -> Result<(), Error> {
        Ok(())
    }
}
struct Source {
    calls: Rc<Cell<usize>>,
    fail_once: bool,
}
impl AddressSource for Source {
    fn visit(
        &mut self,
        p: PeerId,
        _: u64,
        start: usize,
        _: NonZeroUsize,
        visitor: &mut dyn FnMut(&[u8]) -> Result<VisitControl, Error>,
    ) -> Result<Visit, Error> {
        assert_eq!(p, PeerId([9; 32]));
        assert_eq!(start, 0);
        self.calls.set(self.calls.get() + 1);
        let control = visitor(b"tcp-127.0.0.1:42")?;
        if self.fail_once {
            self.fail_once = false;
            return Err(Error::Io);
        }
        Ok(Visit {
            cursor: usize::from(control == VisitControl::Continue),
            finished: control == VisitControl::Continue,
        })
    }
}
fn registration() -> [u8; 16] {
    let mut b = [0; 16];
    b[..2].copy_from_slice(&16_u16.to_be_bytes());
    b[2..4].copy_from_slice(&1211_u16.to_be_bytes());
    b[4..8].copy_from_slice(&1_u32.to_be_bytes());
    b[12..].copy_from_slice(b"tcp\0");
    b
}
async fn frame(s: &mut UnixStream) -> Result<Vec<u8>, std::io::Error> {
    let mut h = [0; 4];
    s.read_exact(&mut h).await?;
    let n = usize::from(u16::from_be_bytes([h[0], h[1]]));
    if n < 4 {
        return Err(std::io::ErrorKind::InvalidData.into());
    }
    let mut b = vec![0; n];
    b[..4].copy_from_slice(&h);
    s.read_exact(&mut b[4..]).await?;
    Ok(b)
}
fn runtime() -> Result<tokio::runtime::Runtime, std::io::Error> {
    tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
}
#[test]
fn original_source_error_after_admission_retains_one_create_and_cancel_retires_only_demand()
-> Result<(), Box<dyn std::error::Error>> {
    runtime()?.block_on(async{
  let mut key=Key(EddsaPrivateKey::from_seed([1;32]));let mut server=Server::new(Engine::new(key.identity(),Limits::default())?,8,65535)?;
  let(a,mut app)=UnixStream::pair()?;let(c,mut comm)=UnixStream::pair()?;server.admit(Connection::from_unix(a))?;server.admit(Connection::from_unix(c))?;
  let done=Rc::new(Cell::new(false));let canceled=Rc::new(Cell::new(false));let requests=Rc::new(Cell::new(usize::MAX));let creates=Rc::new(Cell::new(usize::MAX));let calls=Rc::new(Cell::new(0));let errors=Rc::new(Cell::new(0));
  let mut source=Source{calls:calls.clone(),fail_once:true};let mut rng=Random;let mut store=Store;
  let driver=async{let mut now=100_u64;let mut timer=tokio::time::interval(Duration::from_millis(1));while !done.get(){
    match server.discover(now,100,&mut source,NonZeroUsize::MIN){Ok(_)=>{},Err(Error::Io)=>errors.set(errors.get()+1),Err(e)=>return Err(Box::<dyn std::error::Error>::from(e))}
    requests.set(server.engine().snapshot().application_suggestions);creates.set(server.engine().snapshot().pending_address_creates);
    if canceled.get()&&requests.get()==0 {done.set(true);break;}
    tokio::select!{r=server.step(None,now,&mut key,&mut rng,&mut store)=>{r?;},_=timer.tick()=>{now+=1000;}}
   }Ok::<(),Box<dyn std::error::Error>>(())};
  let scenario=async{
   comm.write_all(&registration()).await?;let p=Preference{priority:0,bandwidth:0,peer:PeerId([9;32])};let mut raw=[0;44];p.encode(false,&mut raw)?;
   for b in raw {app.write_all(&[b]).await?;tokio::task::yield_now().await;}
   let actual=frame(&mut comm).await?;assert_eq!(&actual[2..4],&1206_u16.to_be_bytes());assert_eq!(&actual[8..40],&p.peer.0);assert_eq!(&actual[40..],b"tcp-127.0.0.1:42\0");
   p.encode(true,&mut raw)?;raw[4..8].fill(0xff);raw[40..44].fill(0xff);app.write_all(&raw).await?;canceled.set(true);
   while !done.get(){tokio::task::yield_now().await;}Ok::<(),Box<dyn std::error::Error>>(())
  };
  tokio::time::timeout(Duration::from_secs(3),async{tokio::try_join!(driver,scenario)}) .await??;
  assert_eq!(errors.get(),1);assert_eq!(calls.get(),2);assert_eq!(requests.get(),0);assert_eq!(creates.get(),1);
  assert!(tokio::time::timeout(Duration::from_millis(10),frame(&mut comm)).await.is_err());server.shutdown()?;Ok(())
 })
}
#[test]
fn partial_application_eof_does_not_issue_demand_and_later_full_request_has_new_owner()
-> Result<(), Box<dyn std::error::Error>> {
    runtime()?.block_on(async{
  let mut key=Key(EddsaPrivateKey::from_seed([1;32]));let mut server=Server::new(Engine::new(key.identity(),Limits::default())?,8,65535)?;
  let(a,mut old)=UnixStream::pair()?;let(b,mut fresh)=UnixStream::pair()?;let(c,mut comm)=UnixStream::pair()?;server.admit(Connection::from_unix(a))?;server.admit(Connection::from_unix(b))?;server.admit(Connection::from_unix(c))?;
  let calls=Rc::new(Cell::new(0));let mut source=Source{calls:calls.clone(),fail_once:false};let mut rng=Random;let mut store=Store;let done=Rc::new(Cell::new(false));let retired=Rc::new(Cell::new(false));
  let driver=async{let mut timer=tokio::time::interval(Duration::from_millis(1));while !done.get(){server.discover(100,100,&mut source,NonZeroUsize::MIN)?;tokio::select!{r=server.step(None,100,&mut key,&mut rng,&mut store)=>{r?;},_=timer.tick()=>{}}if retired.get(){assert_eq!(server.engine().snapshot().application_suggestions,0);retired.set(false);}}Ok::<(),Box<dyn std::error::Error>>(())};
  let scenario=async{comm.write_all(&registration()).await?;old.write_all(&[0]).await?;drop(old);retired.set(true);while retired.get(){tokio::task::yield_now().await;}assert_eq!(calls.get(),0);
   let mut raw=[0;44];Preference{priority:0,bandwidth:0,peer:PeerId([9;32])}.encode(false,&mut raw)?;fresh.write_all(&raw).await?;let out=frame(&mut comm).await?;assert_eq!(&out[2..4],&1206_u16.to_be_bytes());done.set(true);Ok::<(),Box<dyn std::error::Error>>(())};
  tokio::time::timeout(Duration::from_secs(3),async{tokio::try_join!(driver,scenario)}).await??;assert_eq!(calls.get(),1);server.shutdown()?;Ok(())
 })
}

#[test]
fn full_suggestion_quota_closes_only_refused_application_not_shared_service()
-> Result<(), Box<dyn std::error::Error>> {
    runtime()?.block_on(async{
  let mut key=Key(EddsaPrivateKey::from_seed([1;32]));let mut server=Server::new(Engine::new(key.identity(),Limits{peers:1,..Limits::default()})?,8,65535)?;
  let(a,mut accepted)=UnixStream::pair()?;let(b,mut refused)=UnixStream::pair()?;let(c,mut comm)=UnixStream::pair()?;server.admit(Connection::from_unix(a))?;server.admit(Connection::from_unix(b))?;server.admit(Connection::from_unix(c))?;
  let calls=Rc::new(Cell::new(0));let mut source=Source{calls:calls.clone(),fail_once:false};let mut rng=Random;let mut store=Store;let done=Rc::new(Cell::new(false));let cancel_sent=Rc::new(Cell::new(false));let count=Rc::new(Cell::new(usize::MAX));
  let driver=async{let mut now=100;let mut timer=tokio::time::interval(Duration::from_millis(1));while !done.get(){server.discover(now,100,&mut source,NonZeroUsize::MIN)?;count.set(server.engine().snapshot().application_suggestions);if cancel_sent.get()&&count.get()==0 {done.set(true);break;}tokio::select!{r=server.step(None,now,&mut key,&mut rng,&mut store)=>{r?;},_=timer.tick()=>{now+=100_000;}}}Ok::<(),Box<dyn std::error::Error>>(())};
  let scenario=async{comm.write_all(&registration()).await?;let p=Preference{priority:0,bandwidth:0,peer:PeerId([9;32])};let mut raw=[0;44];p.encode(false,&mut raw)?;accepted.write_all(&raw).await?;let original=frame(&mut comm).await?;assert_eq!(&original[8..40],&p.peer.0);
   raw[8..40].fill(10);refused.write_all(&raw).await?;let mut byte=[0;1];assert_eq!(refused.read(&mut byte).await?,0);assert_eq!(count.get(),1);
   p.encode(true,&mut raw)?;accepted.write_all(&raw).await?;cancel_sent.set(true);while !done.get(){tokio::task::yield_now().await;}Ok::<(),Box<dyn std::error::Error>>(())};
  tokio::time::timeout(Duration::from_secs(3),async{tokio::try_join!(driver,scenario)}).await??;assert_eq!(count.get(),0);assert!(calls.get()>=1);server.shutdown()?;Ok(())
 })
}
