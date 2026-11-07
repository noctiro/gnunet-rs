#!/usr/bin/env python3
"""Write the explicit STATISTICS operation/callback inventory; never award credit."""
import hashlib
import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
OUTPUT = ROOT / 'spec/gnunet/api'


def document():
    source = 'src/service/statistics/statistics_api.c'
    # A concrete test obligation records observable behavior rather than a
    # misleading function-count percentage. All obligations start pending.
    groups = {
        'create': [
            ('disabled', 'YES DISABLE returns no handle; missing, invalid or non-YES does not disable it.'),
            ('lazy', 'Create stores subsystem/configuration and starts at 1ms backoff without connecting.'),
            ('subsystem', 'SET/UPDATE use exactly the creating subsystem; GET/WATCH may select another subsystem.'),
            ('config', 'Official configuration selects service transport/activation; invalid or unavailable transport remains an explicit failure/retry state.'),
        ],
        'destroy': [
            ('immediate', 'sync_first=false retires watches, queued actions and transport without subsequent callbacks.'),
            ('current-get', 'Immediate destroy fails a non-aborted current GET once; explicit cancellation/iterator abort suppress disconnect continuation.'),
            ('defer-condition', 'Pinned C defers sync destruction only when MQ exists and its non-in-flight queue length is nonzero.'),
            ('drain', 'Deferred destruction removes queued GET/WATCH actions, retains setters and current GET stream tombstone, then sends DISCONNECT.'),
            ('confirm', 'Only expected DISCONNECT_CONFIRM acknowledges processing; this is not a filesystem durability claim.'),
            ('deadline', 'Deferred deadline is admission time plus 5*current backoff; later progress/END does not extend it.'),
            ('failure', 'Connection loss/deadline/disconnected shutdown reports discarded or unknown submitted mutations rather than fabricated flush success.'),
            ('callback-authority', 'Final destruction revokes all callback/epoch authority, including stale socket completions.'),
        ],
        'get': [
            ('wildcards', 'Independent null/empty subsystem and name are wildcards.'),
            ('queue', 'Multiple admitted GETs queue FIFO; there is one current untagged GET until END or connection failure.'),
            ('values', 'Each VALUE belongs to the original operation, retains persistence/opaque names and borrows frame data only for callback use.'),
            ('watch-interleave', 'WATCH_VALUE can interleave with a current GET without completing or corrupting it.'),
            ('end', 'Exact END completes once, resets backoff to 1ms and permits the next queued action.'),
            ('abort-iterator', 'Iterator abort suppresses subsequent VALUE callbacks but drains to END and retains the successful completion continuation.'),
            ('failure', 'A malformed response for a registered STATISTICS handler or transport failure retires the current GET once; well-framed messages without a registered client handler are ignored and neither complete nor cancel it. Queued unsubmitted operations remain owned for retry.'),
            ('callback-lifetime', 'GET completion cannot synchronously destroy the same owner; safe Rust reentrancy/lifetime constraints must preserve this boundary.'),
            ('bounds', 'Every queue/name/terminal capacity rejection preserves prior IDs, queue order and callback authority.'),
        ],
        'get_cancel': [
            ('queued', 'Queued cancellation removes only its original operation, clears continuation and does not submit its request.'),
            ('current', 'Current cancellation disables callbacks/continuation but retains the untagged tombstone until END/disconnect; socket is not closed solely to cancel.'),
            ('late', 'Stale/cancelled operation IDs never affect a later operation or a reused slot.'),
            ('buffered', 'Accepted cancellation is processed before another already-buffered VALUE can call the old callback.'),
        ],
        'set': [
            ('absolute', 'SET uses unsigned absolute value, owner subsystem, exact name and the requested persistence flag.'),
            ('replace', 'Pending same-name SET+SET uses latest value/persistence without modifying an in-flight envelope.'),
            ('coalesce-order', 'Coalescing scans the full pending list and may reach an earlier setter across an intervening GET.'),
            ('update-to-set', 'A new SET overrides a pending UPDATE and changes its kind to absolute.'),
            ('queue-atomic', 'Capacity refusal leaves the earlier value/persistence, FIFO order and completion ownership unchanged.'),
            ('submission', 'MQ submission/first attempt/full write are distinct; a submitted setter has no remote acknowledgement and is not automatically replayed after loss.'),
        ],
        'update': [
            ('signed', 'UPDATE encodes a signed delta as the official relative SET bit pattern.'),
            ('zero', 'A new update(0) is a complete no-op including persistence and row creation.'),
            ('absolute-pending', 'Pending absolute SET+UPDATE wraps positive addition and clamps negative subtraction to zero; defined INT64_MIN magnitude is used.'),
            ('relative-pending', 'Pending UPDATE+UPDATE wraps the unsigned delta sum; a coalesced zero remains an actual queued UPDATE.'),
            ('persistence', 'Latest persistence wins for a nonzero new setter, even after coalescing.'),
            ('timeout', 'Pinned C assigns a two-second timeout field but never enforces it; explicit optional Rust deadlines must not masquerade as reference expiry behavior.'),
        ],
        'watch': [
            ('literal', 'WATCH treats empty names literally, not as GET wildcards, and admits duplicate subscriptions separately.'),
            ('no-ack', 'Submission has no WATCH acknowledgement; zero initial value need not notify.'),
            ('initial', 'Nonzero value notifies immediately; first SET of an unset watched zero row notifies; later equal values suppress per watch.'),
            ('ordering', 'Queued registrations preserve actual transport order and consume connection-local WIDs, including cancelled tombstones still queued on that connection.'),
            ('callback', 'Notification names derive from original registration; watcher return values do not cancel it.'),
            ('flags', 'Reserved nonzero is diagnosed but retained; server persistence flag2 is interpreted with raw flags available, recording the C-client high-bit discrepancy.'),
            ('reconnect', 'MQ recreation retains pending non-watch actions, removes old WATCH action copies, and appends live registrations in original ordinal order with fresh WIDs.'),
            ('epochs', 'Old connection IDs/partial frames cannot mutate new registration mappings or deliver a callback to a replacement watch.'),
        ],
        'watch_cancel': [
            ('local', 'Cancellation is local only: no wire unwatch; the server releases its watch on real disconnect.'),
            ('identity', 'The selected original subscription is cancelled; duplicate names/callback contexts remain distinct.'),
            ('queued-copy', 'A previously queued registration copy may still transmit and its WID is a cancelled tombstone, not authority for a reused logical slot.'),
            ('reconnect-hole', 'Cancelled slots do not shift callback identity after reconnect; logical IDs and fresh connection WID mappings remain separate.'),
        ],
    }
    mappings = {
        'create': ['gnunet_client::statistics_handle::StatisticsHandle::new', 'gnunet_ipc_unix::handle::StatisticsHandle::from_config'],
        'destroy': ['gnunet_client::statistics_handle::StatisticsHandle::begin_destroy', 'gnunet_ipc_unix::handle::StatisticsHandle::destroy'],
        'get': ['gnunet_client::statistics_handle::StatisticsHandle::get', 'gnunet_ipc_unix::handle::StatisticsHandle::get'],
        'get_cancel': ['gnunet_client::statistics_handle::StatisticsHandle::get_cancel', 'gnunet_ipc_unix::handle::CallbackContext::get_cancel'],
        'set': ['gnunet_client::statistics_handle::StatisticsHandle::set', 'gnunet_ipc_unix::handle::StatisticsHandle::set'],
        'update': ['gnunet_client::statistics_handle::StatisticsHandle::update', 'gnunet_ipc_unix::handle::StatisticsHandle::update'],
        'watch': ['gnunet_client::statistics_handle::StatisticsHandle::watch', 'gnunet_ipc_unix::handle::StatisticsHandle::watch'],
        'watch_cancel': ['gnunet_client::statistics_handle::StatisticsHandle::watch_cancel', 'gnunet_ipc_unix::handle::CallbackContext::watch_cancel'],
    }
    functions=[]
    for operation,cases in groups.items():
        symbol='GNUNET_STATISTICS_'+operation
        functions.append({'symbol':symbol,'criterion_id':'api.'+symbol,'status':'in_progress','rust_equivalence_candidates':mappings[operation],
                          'reference_sources':[{'path':'src/include/gnunet_statistics_service.h','symbol':symbol},{'path':source,'symbol':symbol}],
                          'cases':[{'id':'statistics.client.'+operation+'.'+name,'required':True,'requirement':requirement,'status':'missing','test_commands':[],'verification':None} for name,requirement in cases]})
    result={'schema':1,'subsystem':'statistics','public_functions':functions,
            'callbacks':[{'name':'GNUNET_STATISTICS_Iterator','requirement':'GET Continue/AbortIteration differs from ignored WATCH return; borrowed names/value lifetime and persistence flags are explicit.'},
                         {'name':'GNUNET_STATISTICS_Callback','requirement':'Exactly-once eligible GET continuation; cancellation, abort, disconnect and END are distinct.'}],
            'wire_operations':[{'type':168,'name':'STATISTICS_SET'},{'type':169,'name':'STATISTICS_GET'},{'type':170,'name':'STATISTICS_VALUE'},{'type':171,'name':'STATISTICS_END'},{'type':172,'name':'STATISTICS_WATCH'},{'type':173,'name':'STATISTICS_WATCH_VALUE'},{'type':174,'name':'STATISTICS_DISCONNECT'},{'type':175,'name':'STATISTICS_DISCONNECT_CONFIRM'}],
            'cross_operation_cases':[
                {'id':'statistics.client.reconnect.backoff','required':True,'requirement':'Deterministic 1ms doubling backoff capped at15minutes; only successful END resets it. Initial virtual MQ creation differs from socket readiness.','status':'missing','test_commands':[],'verification':None},
                {'id':'statistics.client.transport.partial-write','required':True,'requirement':'First send attempt, MQ non-in-flight queue length and full frame write are distinct; one partial envelope cannot corrupt or prematurely complete the next.','status':'missing','test_commands':[],'verification':None},
            ],
            'reference_discrepancies':[
                {'id':'statistics.watch.persistence-bit','state':'observed_normal_c','source':'statistics_api.c:handle_statistics_watch_value vs gnunet-service-statistics.c:notify_change','decision':'Retain server bit2 and raw flags; do not rewrite the official wire to match the C-client high-UID-bit mistake.','runtime_proof_required':True},
                {'id':'statistics.watch.reconnect-hole','state':'observed_normal_c','source':'statistics_api.c:watch_cancel,try_connect,handle_statistics_watch_value','decision':'Separate stable logical watch identity from fresh per-connection WIDs. Normal C public-owner traces observe suppression of a new WID0 watch and misrouting of WID1 into the old logical slot; current-source regression evidence remains required.','runtime_proof_required':True},
                {'id':'statistics.client.missing-hostname','state':'observed_normal_c_safety_error','source':'src/lib/util/client.c:GNUNET_CLIENT_connect','decision':'A valid Unix endpoint remains usable without a TCP hostname; Rust must not reproduce the normal C NULL-hostname dereference. Preserve source-bound negative reference evidence without treating the crash as a required Rust behavior.','runtime_proof_required':True},
                {'id':'statistics.watch.pre-mq-notification','state':'observed_normal_c_invalid_peer_acceptance','source':'statistics_api.c:GNUNET_STATISTICS_watch,handle_statistics_watch_value','decision':'Normal C accepts a WID for a queued logical watch even before its WATCH MQ envelope exists. Rust requires connection-local WID assignment at actual MQ admission before delivering a callback; this is an explicit protocol/ownership boundary, not a memory-safety necessity. Valid service interaction remains covered separately.','runtime_proof_required':True},
                {'id':'statistics.disconnect.pre-write-confirm','state':'observed_normal_c_invalid_peer_acceptance','source':'statistics_api.c:handle_disconnect_confirm,statistics_transmit','decision':'Normal C accepts confirmation once its disconnect envelope enters the MQ, even if earlier data remains physically unwritten. Rust requires the original barrier frame to be fully written before reporting ProcessingConfirmed. This preserves result integrity and is an explicit stricter invalid-peer policy, not a claim of identical C error acceptance or a memory-safety necessity.','runtime_proof_required':True},
                {'id':'statistics.setter.int64-min','state':'source_confirmed_undefined_C_boundary','source':'statistics_api.c:add_setter_action and gnunet-service-statistics.c:handle_set','decision':'Use defined unsigned_abs magnitude; retain compiler-profile differential cases without claiming ISO-C UB portability.','runtime_proof_required':True},
                {'id':'statistics.disconnect.persistence','state':'source_confirmed','source':'statistics_api.c:handle_disconnect_confirm comment vs service handle_disconnect/save','decision':'Confirmation is processing, never independently verified filesystem durability.','runtime_proof_required':True},
            ],
            'full_client_api_verified':False,'evidence_policy':'Every criterion needs current source/binary/log-bound reference evidence validated by the parent conformance checker. Mapping names, source observations and test counts confer no verification credit.'}
    return result


def generate():
    result=document()
    (OUTPUT/'statistics.json').write_text(json.dumps(result,indent=2)+'\n')
    catalog=json.loads((OUTPUT/'catalog.json').read_text())
    catalog['files']=[row for row in catalog['files'] if row['role']!='statistics']
    catalog['files'].append({'role':'statistics','path':'spec/gnunet/api/statistics.json','sha256':hashlib.sha256((OUTPUT/'statistics.json').read_bytes()).hexdigest()})
    (OUTPUT/'catalog.json').write_text(json.dumps(catalog,indent=2)+'\n')
    print('statistics public functions',len(result['public_functions']),'required behavioral cases',sum(len(row['cases']) for row in result['public_functions'])+len(result['cross_operation_cases']))


if __name__=='__main__':
    generate()
