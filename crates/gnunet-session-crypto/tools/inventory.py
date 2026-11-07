#!/usr/bin/env python3
"""Read-only complete public crypto-header gap and lexical-consumer inventory."""
import argparse,hashlib,json,re
from pathlib import Path
from collections import Counter

def digest(path):return hashlib.sha256(path.read_bytes()).hexdigest()

def main():
 p=argparse.ArgumentParser(description=__doc__);p.add_argument('--repository',required=True,type=Path);p.add_argument('--source',required=True,type=Path);p.add_argument('--output',required=True,type=Path);a=p.parse_args();repo=a.repository.resolve();source=a.source.resolve();output=a.output.resolve();package=Path(__file__).resolve().parents[1]
 for root in [repo,source,package]:
  if output.is_relative_to(root) or root.is_relative_to(output):p.error('output overlaps source')
 output.mkdir(parents=True,exist_ok=False);catalog=repo/'spec/gnunet/api/declarations.json';data=json.loads(catalog.read_text());header='src/include/gnunet_crypto_lib.h';ds=[d for d in data['declarations'] if d['header']==header];ids={d['id'] for d in ds};functions=[f for f in data['functions'] if set(f['declaration_ids'])&ids];assert len(functions)==226
 consumers={f['id']:[] for f in functions}
 for path in sorted((source/'src').rglob('*.c')):
  if path.name.startswith(('test_','perf_')) or path.parent==source/'src/lib/util' and path.name.startswith('crypto_'):continue
  text=path.read_text(errors='replace');masked=re.sub(r'/\*.*?\*/|//[^\n]*',lambda m:'\n'*m.group().count('\n'),text,flags=re.S)
  for match in re.finditer(r'\b(GNUNET_CRYPTO_\w+)\s*\(',masked):
   name=match[1]
   if name in consumers:consumers[name].append({'path':str(path.relative_to(source)),'line':masked.count('\n',0,match.start())+1})
 existing={
  'zero_keys':('erase','Compiler-resistant caller slice erasure; pointer ABI replaced by safe slices.'),
  'hash':('hash512','Standard SHA512, no framing.'),
  'eddsa_key_get_public':('eddsa::EddsaPrivateKey::public_key','Exact32-byte seed/public derivation.'),
  'eddsa_key_create':('eddsa::EddsaPrivateKey::generate','Caller entropy; no ambient RNG.'),
  'eddsa_key_clear':('eddsa::EddsaPrivateKey drop','Owned secret lifetime replaces in-place C pointer clear.'),
  'eddsa_sign_':('eddsa::EddsaPrivateKey::sign','Exact expected-purpose region with safe length bounds.'),
  'eddsa_verify_':('eddsa::EddsaPublicKey::verify','Canonical/small-order strict verification; service authorization remains separate.'),
  'ecdsa_key_create':('gns::PkeySecret::generate','Official clamped initial scalar.'),
  'ecdsa_key_clear':('gns::PkeySecret drop','Owned zeroizing lifetime.'),
  'ecdsa_key_get_public':('gns::PkeySecret::public_key','Existing bounded nonzero-scalar constructor profile.'),
  'ecdsa_private_key_derive':('gns::PkeySecret::derive','NFC label/context passed explicitly.'),
  'ecdsa_public_key_derive':('gns::derive_public','Public Edwards key blinding.'),
  'ecdsa_sign_derived':('gns::PkeyDerivedSecret::sign','Derived ECDSA/RFC6979 signature.'),
  'ecdsa_verify_':('gns::verify_pkey','Purpose-bound signature verification.'),
  'eddsa_private_key_derive':('gns::EdkeySecret::derive','Seed-to-expanded derived scalar/prefix.'),
  'eddsa_public_key_derive':('gns::derive_public','Existing EDKEY public derivation.'),
  'eddsa_sign_derived':('gns::EdkeyDerivedSecret::sign','Derived Ed25519 scalar/prefix signing.'),
  'hkdf_gnunet_v':('hkdf_gnunet','Legacy HMAC-SHA512 extract/HMAC-SHA256 expand; not standard split HKDF.'),
  'aes_ctr':('symmetric::aes256ctr','Whole-message AES256CTR; persistent TCP stream added in candidate.'),
  'xsalsa20poly1305_encrypt':('symmetric::xsalsa20poly1305_seal','Tag-first GNS secretbox.'),
  'xsalsa20poly1305_decrypt':('symmetric::xsalsa20poly1305_open','Authenticate before plaintext; failed output erasure.'),
 }
 added={
  'ecc_ecdh':('exchange::EcdheSecret::exchange_hashed','SHA512 of raw X25519.'),
  'x25519_ecdh':('exchange::EcdheSecret::exchange_raw','Raw32 DH and all-zero rejection.'),
  'ecdh_x25519':('exchange::EcdheSecret::exchange_raw','Same source raw-DH operation, distinct from hashed legacy path.'),
  'ecdhe_key_get_public':('exchange::EcdheSecret::public_key','RFC7748 clamped base multiplication.'),
  'ecdhe_key_create':('exchange::EcdheSecret::generate','32 raw entropy bytes, not HPKE DeriveKeyPair.'),
  'ecdhe_key_clear':('exchange::EcdheSecret drop','Zeroizing scalar owner; no Clone/Debug/export.'),
  'eddsa_ecdh':('from_eddsa_seed + exchange_hashed','SHA512(seed) first32/clamp, then SHA512(DH).'),
  'ecdh_eddsa':('exchange_edwards_hashed','Normal libsodium subgroup conversion then SHA512(DH).'),
  'ecdsa_ecdh':('from_bytes + exchange_hashed','Raw PKEY scalar input; X25519 clamp at use. Valid generated PKEY profile.'),
  'ecdh_ecdsa':('exchange_edwards_hashed','Same Edwards-public conversion, tested with generated/clamped PKEY fixtures.'),
  'hpke_sk_to_x25519':('from_eddsa_seed / from_bytes','Both official EDDSA and ECDSA branches; no unrecognized tag fallback.'),
  'hpke_pk_to_x25519':('exchange::EcdhePublic::from_edwards','Both official key tags use same normal subgroup/map operation.'),
  'hpke_kem_encaps_norand':('exchange::kem_encapsulate','DHKEM0x0020 only; exact HPKE-v1/KEM labels and enc||pkR context.'),
  'hpke_kem_encaps':('exchange::kem_encapsulate_random','Explicit32-byte ephemeral entropy, then0x0020.'),
  'hpke_kem_decaps':('exchange::kem_decapsulate','Exact0x0020 reverse path and low-order rejection.'),
  'eddsa_kem_encaps':('from_edwards + kem_encapsulate_random','Composition with normal EdDSA public conversion.'),
  'eddsa_kem_decaps':('from_eddsa_seed + kem_decapsulate','Composition with normal seed conversion.'),
  'hpke_sk_create2':('exchange::EcdheSecret::derive_hpke','0x0020 dkp_prk/sk labels, then RFC9180 serialized clamp.'),
  'hpke_sk_create':('exchange::EcdheSecret::generate_hpke','Exactly64 entropy IKM bytes, not raw ECDHE32.'),
  'hpke_sk_clear':('exchange::EcdheSecret drop','Only supported X25519 owner; no C union tag/pointer ABI.'),
  'hpke_sk_get_public':('exchange::EcdheSecret::public_key','Only actual supported key type0.'),
  'hpke_pk_get_length':('EcdhePublic encoded36','Type0 fixed36 bytes; no unsupported suite negotiation.'),
  'write_hpke_pk_to_buffer':('exchange::EcdhePublic::encode_hpke','BE32 type0 +32; capacity rejection atomic.'),
  'read_hpke_pk_from_buffer':('exchange::EcdhePublic::decode_hpke','Return consumed36; extra trailing bytes retained.'),
  'hkdf_extract':('hkdf_extract','Standard HMAC-SHA256 extract, ordered IKM slices.'),
  'hkdf_expand_v':('Prk::expand / hkdf_expand','Standard SHA256 expand, unframed info slices; oversize erased by policy.'),
  'hash_context_start':('transcript::Hash512State::new','No-allocation incremental SHA512.'),
  'hash_context_read':('transcript::Hash512State::update','Exact appended bytes, no extra domain.'),
  'hash_context_copy':('transcript::Hash512State::clone','Independent public transcript checkpoint.'),
  'hash_context_finish':('transcript::Hash512State::finish','Consume context and return64 bytes.'),
  'hash_context_abort':('Hash512State drop','No C heap context/pointer ownership.'),
  'hmac_raw':('transcript::hmac512','HMAC-SHA512 over caller key/ordered parts; erased pads.'),
  'hmac':('transcript::hmac512 with64-byte AuthKey / TcpStream::hmac','Official64-byte key construction; no tag truncation.'),
  'aead_create_key':('caller Entropy into32-byte secret owner','Caller entropy capability; exact XChaCha key width, no host RNG.'),
  'aead_encrypt':('aead::xchacha20poly1305_seal','Nonce24 and detached tag16, exact AAD.'),
  'aead_decrypt':('aead::xchacha20poly1305_open','Validate before plaintext; failed range erased.'),
 }
 # Entropy->AEAD key generation currently available through opaque constructor
 # is not a dedicated public operation: keep the API obligation explicitly partial.
 partial={'aead_create_key':'No dedicated AeadSecret generate API yet; caller-owned32-byte keys are accepted.','ecdsa_sign_':'Derived PKEY signing exists, but no public base-scalar signing method.','eddsa_sign_raw':'Peer signing purpose API exists; arbitrary unprefixed data API absent.','eddsa_verify_raw':'Peer purpose verifier exists; arbitrary raw-region API absent.','eddsa_key_get_public_from_scalar':'Derived public math exists, no general scalar-entry public function.','blindable_key_get_public':'ZoneSecret::public_key covers PKEY/EDKEY, generic util wrapper separate.','read_blindable_pk_from_buffer':'ZoneKey decoding covers GNS representation; util consumed-length/error policy not formally mapped.','write_blindable_pk_to_buffer':'ZoneKey encoding exists; generic util wrapper/partial writes need mapping.','blindable_pk_get_length':'GNS typed key width exists; general API ownership mapping not closed.','random_block':'Entropy trait is a caller capability, not the full host CSPRNG public API.','hash_to_enc':'Shared Crockford byte encoding exists; full utility API mapping/normal profile still pending.','hash_from_string2':'Shared decoding exists; exact helper API aliases/length and errors require mapping.'}
 def group(n):
  for needles,g in [(['hpke_elligator','ecdhe_elligator'],'elligator-0x0022'),(['hpke_'],'hpke-context-and-codecs'),(['rsa_'],'rsa-fdh-blind-signatures'),(['paillier_'],'paillier'),(['cs_'],'clause-schnorr'),(['edx25519_'],'edx25519-hd'),(['ecc_'],'ecc-utility'),(['ecdsa_','eddsa_','ecdh_','ecdhe_','x25519_'],'elliptic-keys-signatures'),(['symmetric_'],'legacy-aes-twofish-cfb'),(['hash_file'],'host-file-hashing'),(['hash_','hmac','hkdf','kdf_'],'hash-kdf-mpi'),(['random_'],'entropy-random'),(['crc'],'crc'),(['blind','bsign','ub_sig','unblinded','blinding','message_blind','get_blinding','read_blind','write_blind','private_key'],'generic-blindable-and-blind-signatures')]:
   if any(n.startswith(q) for q in needles):return g
  return 'host-key-setup-or-shared'
 rows=[]
 for f in functions:
  full=f['id'];n=full.removeprefix('GNUNET_CRYPTO_');status='missing';rust=[];detail='No current complete Rust equivalent. Remains required; no catalog verification upgrade.'
  if n in existing:status='existing_primitive';rust=['gnunet-crypto::'+existing[n][0]];detail=existing[n][1]
  if n in added:status='tmp_candidate';rust=['candidate::'+added[n][0]];detail=added[n][1]
  if n in partial:status='partial_foundation';detail=partial[n]
  rows.append({'official':full,'signatures':f['signatures'],'scope':f['scope'],'deprecated':f['deprecated'],'category':group(n),'assessment':status,'rust_equivalence':rust,'boundary':detail,'consumers':consumers[full],'consumer_scope':'Lexical C call occurrences outside util crypto implementations and tests; explicit normal profile/conditional review required, not a preprocessed full call graph.'})
 surfaces=[s for s in data['surfaces'] if s.get('header')==header or set(s.get('declaration_ids',[]))&ids]
 report={'status':'inventory-only','profile':data['profile'],'source_header':{'path':header,'sha256':digest(source/header)},'catalog_sha256':digest(catalog),'function_count':len(rows),'function_assessments':dict(Counter(r['assessment'] for r in rows)),'functions':rows,'nonfunction_declarations':[d for d in ds if d['kind']!='FunctionDecl'],'nonfunction_surfaces':surfaces,'existing_scope_documents':{str(p.relative_to(repo)):digest(p) for p in [repo/'crates/gnunet-crypto/README.md',repo/'crates/gnunet-gnscrypto/UPSTREAM.md',repo/'crates/gnunet-hello/UPSTREAM.md']},'not_completeness_evidence':True,'selected_chain':'raw/hashed X25519 + EdDSA/PKEY conversion +plainDHKEM0x0020 +standardHKDF +CAKE role/transcript/record material +XChaCha AEAD; persistent TCP CTR+HMAC; UDP KDF only, AES-GCM and Elligator missing.'}
 (output/'api-gap.json').write_text(json.dumps(report,indent=2)+'\n');lines=['# Fixed v0.29.1 public crypto API gap table','',f'All {len(rows)} function declarations in gnunet_crypto_lib.h are represented. Status is a review assessment, not an acceptance-ledger upgrade. Nonfunction types/macros are retained losslessly in api-gap.json.','', '| Official API | Assessment | Rust boundary / remaining work |','|---|---|---|']
 for row in rows:lines.append('| `'+row['official']+'` | '+row['assessment']+' | '+('; '.join(row['rust_equivalence'])+'; ' if row['rust_equivalence'] else '')+row['boundary']+' |')
 (output/'API-GAPS.md').write_text('\n'.join(lines)+'\n');print(json.dumps({'functions':len(rows),'assessments':report['function_assessments'],'nonfunction_surfaces':len(surfaces)}))
if __name__=='__main__':main()
