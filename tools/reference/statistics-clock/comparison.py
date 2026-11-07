"""Common-state projection checks; no C transition implementation."""
import re

def compare(c_trace, rust_stdout):
    c_lines = c_trace.splitlines()
    c_clock = [line for line in c_lines if line.startswith(('backoff|', 'end-reset|'))]
    rust_clock = re.findall(r'(?:backoff\|[^\n]+|end-reset\|[^\n]+)', rust_stdout)
    assert len(c_clock) == 33 and c_clock == rust_clock
    c_io = []
    for line in c_lines:
        fields = line.split('|')
        if fields[0] != 'io' or fields[1] == 'fatal':
            continue
        # C: name,step,offset,non-inflight-length,in-flight,in-flight-call-count,
        # sent-callback-count,continue-call-count,error-count.
        assert fields[4]=='0' and fields[7]=='1' and fields[9]=='0'
        c_io.append('|'.join(['normalized-io', *fields[1:6], str(int(int(fields[8]) != 0)),
                              str(int(int(fields[9]) != 0))]))
    rust_io = re.findall(r'normalized-io\|[^\n]+', rust_stdout)
    assert len(c_io) == 21 and c_io == rust_io
    c_immutable = [line for line in c_lines if line.startswith('immutable|')]
    rust_immutable = re.findall(r'immutable\|[^\n]+', rust_stdout)
    assert len(c_immutable) == 2 and c_immutable == rust_immutable
    c_fatal = next(line.split('|') for line in c_lines if line.startswith('owner-fatal-first|'))
    common_fatal = '|'.join(['normalized-owner-fatal-first', *c_fatal[1:3]])
    assert re.findall(r'normalized-owner-fatal-first\|[^\n]+', rust_stdout) == [common_fatal]
    # The C raw-MQ observer records the write error; the actual public-owner C
    # case above invokes the original mq_error_handler and destroys that MQ.
    # Do not compare the post-error raw-MQ fixture with a retired Rust owner.
    assert next(line for line in c_lines if line.startswith('io|fatal|')) == 'io|fatal|0|0|1|0|0|0|0|1'
    assert c_fatal == ['owner-fatal-first', '0', '1', '1', '1000', '0', '0']
    overflow = next(line.split('|') for line in c_lines if line.startswith('clock-overflow|'))
    assert re.findall(r'normalized-clock-overflow\|[^\n]+', rust_stdout) == ['normalized-clock-overflow|'+overflow[2]]
    return {'equal_common_rows': 58, 'absolute_overflow_target': overflow[2], 'clock_rows': c_clock, 'io_rows': c_io,
            'immutable_rows': c_immutable, 'owner_fatal_first': common_fatal,
            'non_equivalence': ['Repeated zero/EAGAIN/EINTR at offset zero call C MQ_impl_send_in_flight repeatedly, but its actual sent callback runs once. Rust retains one started flag; no callback count is invented.'],
            'comparison_scope': 'Common observable state projections, not identical internal function counts or fabricated C destruction-report fields.'}


