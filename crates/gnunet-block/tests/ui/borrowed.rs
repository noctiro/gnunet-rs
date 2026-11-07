//! Standalone compile fixture: each group retains its distinct creation borrow.
use gnunet_block::{BlockType,GroupState,Hash,MarkSeen,ReturnValue,ReplyEvaluation,callbacks::{PluginFunctions,CallbackContext,Reply},bloom::NativeEndian,plugins::{Clock,KeyResult,Work}};
use gnunet_types::Error;
struct Tag{label:Vec<u8>}
struct TaggedPlugin{marker:u8}
struct TaggedGroup<'a>{tag:&'a Tag,parent:&'a TaggedPlugin,bytes:&'a mut[u8],raw:Option<&'a[u8]>}
impl GroupState for TaggedGroup<'_>{
 fn block_type(&self)->BlockType{BlockType(u32::from(self.parent.marker))}
 fn serialize_into(&self,out:&mut[u8])->Result<Option<usize>,Error>{let n=self.tag.label.len();if out.len()<n{return Err(Error::Capacity);}out[..n].copy_from_slice(&self.tag.label);Ok(Some(n))}
 fn mark_seen(&mut self,_:&[Hash])->MarkSeen{self.bytes[0]=self.tag.label[0];MarkSeen::Marked}
 fn has_merge(&self)->bool{false}
 fn merge_from(&mut self,_:&Self)->Result<ReturnValue,Error>{Err(Error::Unsupported)}
}
impl PluginFunctions for TaggedPlugin{
 type Creation<'a>=&'a Tag;
 type Group<'a>=TaggedGroup<'a>;
 fn types(&self)->&[BlockType]{&[BlockType(101)]}
 fn create_group<'a>(&'a self,_:BlockType,tag:Self::Creation<'a>,raw:Option<&'a[u8]>,_:u32,storage:&'a mut[u8],_:NativeEndian)->Result<Option<TaggedGroup<'a>>,Error>{Ok(Some(TaggedGroup{tag,parent:self,bytes:storage,raw}))}
 fn get_key(&self,_:BlockType,_:&[u8],_:&mut Work<'_>,_:&mut dyn Clock)->Result<KeyResult,Error>{Ok(KeyResult{status:ReturnValue::No,key:None})}
 fn check_query(&self,_:BlockType,_:&Hash,_:Option<&[u8]>)->ReturnValue{ReturnValue::Yes}
 fn check_block(&self,_:BlockType,_:&[u8],_:&mut Work<'_>,_:&mut dyn Clock)->Result<ReturnValue,Error>{Ok(ReturnValue::Yes)}
 fn check_reply<'a>(&self,_:BlockType,_:Option<&mut TaggedGroup<'a>>,_:Reply<'_>,_:&mut Work<'_>,_:&mut dyn Clock)->Result<ReplyEvaluation,Error>where Self:'a{Ok(ReplyEvaluation::More)}
}
fn main()->Result<(),Error>{
 let tag1=Tag{label:b"first".to_vec()};let tag2=Tag{label:b"second".to_vec()};let context=CallbackContext::new([TaggedPlugin{marker:101}],NativeEndian::native());let mut storage1=vec![0;8];let mut storage2=vec![0;8];let raw1=vec![3u8];let raw2=vec![4u8];
 let mut group1=context.create_group(BlockType(101),&tag1,Some(&raw1),0,&mut storage1)?.ok_or(Error::NotReady)?;let mut group2=context.create_group(BlockType(101),&tag2,Some(&raw2),0,&mut storage2)?.ok_or(Error::NotReady)?;
 // lifetime-failure-marker
 assert_eq!(group1.tag.label,b"first");assert_eq!(group2.tag.label,b"second");assert_eq!(group1.raw,Some(raw1.as_slice()));assert_eq!(group2.raw,Some(raw2.as_slice()));assert_eq!(group1.block_type(),BlockType(101));assert_eq!(group2.block_type(),BlockType(101));assert_eq!(group1.mark_seen(&[]),MarkSeen::Marked);assert_eq!(group2.mark_seen(&[]),MarkSeen::Marked);assert_eq!(group1.bytes[0],b'f');assert_eq!(group2.bytes[0],b's');let mut a=[0;6];let mut b=[0;6];assert_eq!(group1.serialize_into(&mut a)?,Some(5));assert_eq!(group2.serialize_into(&mut b)?,Some(6));assert_eq!(&a[..5],b"first");assert_eq!(b,b"second"[..]);Ok(())
}
