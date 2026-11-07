//! Live CLIENT read points against an actual isolated normal C ARM service.
#[path = "../../resolver-broker-std/tests/support/domain.rs"]
mod resolution_domain;
use gnunet_arm_core::{
    FrameSlot,
    client::{Client, ConnectionStatus, Event, Inbound, OperationSlot},
    wire::ArmAbi,
};
use gnunet_arm_host::{
    ChildRegistry, ClientHost, Clock, LaunchLimits, Limits, LiveConfiguration, LocalLauncher,
    Progress,
};
use gnunet_config::Configuration;
use std::{
    io::{self, Write},
    path::PathBuf,
    time::Duration,
};
use tokio::time::Instant;
type Result<T> = std::result::Result<T, Box<dyn std::error::Error>>;
async fn run(
    old: PathBuf,
    new: PathBuf,
    old_port: u16,
    new_port: u16,
    helper: PathBuf,
) -> Result<()> {
    let mut domain = resolution_domain::Domain::new(Configuration::default())?;
    domain.start()?;
    let mut cfg = Configuration::new(Default::default());
    cfg.set_value(
        b"arm",
        b"UNIXPATH",
        Some(old.as_os_str().as_encoded_bytes()),
    )?;
    cfg.set_number(b"arm", b"PORT", u64::from(old_port))?;
    cfg.set_value(b"arm", b"HOSTNAME", Some(b"127.0.0.1"))?;
    let live = LiveConfiguration::new(cfg.duplicate()?);
    let mut registry = ChildRegistry::new(2)?;
    let launcher = LocalLauncher::new(
        cfg.duplicate()?,
        helper,
        LaunchLimits::default(),
        &mut registry,
    )?;
    let mut operations = [OperationSlot::EMPTY; 2];
    let mut slots = [FrameSlot::EMPTY; 4];
    let mut pool = [0; 128];
    let core = Client::new(&mut operations, &mut slots, &mut pool, 1, ArmAbi::U64Align8)?;
    let mut owner = ClientHost::connect_live(
        core,
        live.clone(),
        domain.resolution(),
        launcher,
        Limits::default(),
        Clock::system()?,
        |_| {},
    )?;
    let original = owner.connection_epoch();
    let operation = owner.request_service_list()?;
    cfg.set_number(b"arm", b"PORT", u64::from(new_port))?;
    live.replace(cfg.duplicate()?)?;
    writeln!(io::stdout().lock(), "{{\"event\":\"port-updated\"}}")?;
    let change_at = Instant::now() + Duration::from_millis(40);
    let mut updated = false;
    let mut confirmed = 0;
    let mut listed = 0;
    let mut failure = None;
    let until = Instant::now() + Duration::from_secs(14);
    while listed == 0 {
        if !updated && Instant::now() >= change_at {
            cfg.set_value(
                b"arm",
                b"UNIXPATH",
                Some(new.as_os_str().as_encoded_bytes()),
            )?;
            live.replace(cfg.duplicate()?)?;
            updated = true;
            writeln!(io::stdout().lock(), "{{\"event\":\"unix-updated\"}}")?;
        }
        let step=owner.drive(Some(if updated{until}else{change_at}),|event,_|{let result=(||->Result<()>{match event{Inbound::Event(Event::Connection(status))=>{writeln!(io::stdout().lock(),"{{\"event\":\"connection\",\"status\":{},\"unix_updated\":{updated}}}",match status{ConnectionStatus::Connected=>1,ConnectionStatus::Disconnected=>0,ConnectionStatus::Error=>-1})?;if status!=ConnectionStatus::Connected||!updated{return Err("TCP cache changed or early connection".into());}confirmed+=1;},Inbound::List{operation:id,list}=>{if id!=operation||!list.is_empty()||!updated{return Err("original queued LIST changed".into());}listed+=1;writeln!(io::stdout().lock(),"{{\"event\":\"list\",\"status\":0,\"count\":0,\"unix_updated\":{updated}}}")?;},_=>return Err("original operation failed".into())}Ok(())})();if let Err(error)=result{failure=Some(error);}}).await?;
        if let Some(error) = failure {
            return Err(error);
        }
        if updated && step == Progress::WaitDeadline {
            return Err("native read-point probe timed out".into());
        }
    }
    if owner.connection_epoch() != original || confirmed != 1 || listed != 1 {
        return Err("logical MQ authority changed".into());
    }
    owner.disconnect(|_, _| {})?;
    writeln!(
        io::stdout().lock(),
        "{{\"event\":\"done\",\"confirmed\":{confirmed},\"listed\":{listed},\"failed\":0}}"
    )?;
    Ok(())
}
fn main() -> Result<()> {
    let args: Vec<_> = std::env::args_os().skip(1).collect();
    let old = PathBuf::from(args.first().ok_or("old Unix")?);
    let new = PathBuf::from(args.get(1).ok_or("new Unix")?);
    let old_port = args
        .get(2)
        .and_then(|value| value.to_str())
        .ok_or("old port")?
        .parse()?;
    let new_port = args
        .get(3)
        .and_then(|value| value.to_str())
        .ok_or("new port")?
        .parse()?;
    let helper = PathBuf::from(args.get(4).ok_or("helper")?);
    tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()?
        .block_on(run(old, new, old_port, new_port, helper))
}
