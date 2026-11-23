//! Windows DNS Client queries with native cancellation and default policy.
use super::{Answer, Question};
use gnunet_dns::MAX_NAME_LENGTH;
use std::{
    cell::UnsafeCell,
    ffi::c_void,
    future::Future,
    io,
    mem::size_of,
    net::Ipv4Addr,
    pin::Pin,
    ptr::{self, NonNull},
    sync::{
        Arc, Mutex,
        atomic::{AtomicBool, Ordering},
    },
    task::{Context, Poll},
};
use tokio::sync::{OwnedSemaphorePermit, oneshot};
use windows_sys::Win32::{
    Foundation::{DNS_ERROR_RCODE_NAME_ERROR, DNS_INFO_NO_RECORDS, DNS_REQUEST_PENDING},
    NetworkManagement::Dns::{
        DNS_A_DATA, DNS_AAAA_DATA, DNS_PTR_DATAW, DNS_QUERY_CANCEL, DNS_QUERY_REQUEST,
        DNS_QUERY_REQUEST_VERSION1, DNS_QUERY_RESULT, DNS_QUERY_RESULTS_VERSION1,
        DNS_QUERY_STANDARD, DNS_QUERY_TREAT_AS_FQDN, DNS_RECORDW, DNS_TYPE_A, DNS_TYPE_AAAA,
        DNS_TYPE_PTR, DNSREC_ANSWER, DNSREC_SECTION, DnsCancelQuery, DnsFree, DnsFreeRecordList,
        DnsQueryEx,
    },
};

// A 65,535-byte DNS packet can contain at most this many minimum-sized records.
const MAX_RECORDS: usize = 5956;
type Outcome = io::Result<Vec<Answer>>;

struct Original {
    request: UnsafeCell<DNS_QUERY_REQUEST>,
    _name: Box<[u16]>,
    result: UnsafeCell<DNS_QUERY_RESULT>,
    cancel: UnsafeCell<DNS_QUERY_CANCEL>,
    completed: AtomicBool,
    reply: Mutex<Option<oneshot::Sender<Outcome>>>,
    record_type: u16,
    limit: usize,
    _permit: OwnedSemaphorePermit,
}

#[expect(
    unsafe_code,
    reason = "Request metadata stays immutable, and the native completion and cancellation ports synchronize their own distinct output locations"
)]
// SAFETY: the request's pointers reference a live Arc and its immutable UTF-16
// buffer. Only DNS API writes result and cancel storage. Rust reads the
// result after synchronous return or on native completion.
unsafe impl Send for Original {}

#[expect(
    unsafe_code,
    reason = "Submission and cancellation use native ABI pointers; all shared Rust state is synchronized or immutable"
)]
// SAFETY: only the reactor issues one submit and at most one cancel. The
// completion code reads the original result only after native writes end.
unsafe impl Sync for Original {}

pub(super) struct Request {
    original: Arc<Original>,
    reply: oneshot::Receiver<Outcome>,
}

#[expect(
    unsafe_code,
    reason = "Lend one original request, result, cancellation buffer and callback Arc to the Windows DNS Client"
)]
pub(super) fn start(
    question: Question<'_>,
    limit: usize,
    permit: OwnedSemaphorePermit,
) -> io::Result<Request> {
    let mut reverse = [0; 80];
    let name = question.name(&mut reverse)?;
    let (record_type, query_options) = match question {
        Question::A(_) => (DNS_TYPE_A, DNS_QUERY_STANDARD),
        Question::Aaaa(_) => (DNS_TYPE_AAAA, DNS_QUERY_STANDARD),
        Question::Ptr(_) => (DNS_TYPE_PTR, DNS_QUERY_TREAT_AS_FQDN),
    };
    if name.strip_suffix('.').unwrap_or(name).len() > MAX_NAME_LENGTH
        || name.is_empty()
        || name.as_bytes().contains(&0)
        || limit == 0
    {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "invalid Windows DNS question or answer limit",
        ));
    }

    let name: Box<[u16]> = name.encode_utf16().chain([0]).collect();
    let (send, reply) = oneshot::channel();
    let original = Arc::new(Original {
        request: UnsafeCell::new(DNS_QUERY_REQUEST {
            Version: DNS_QUERY_REQUEST_VERSION1,
            QueryName: name.as_ptr(),
            QueryType: record_type,
            QueryOptions: u64::from(query_options),
            pDnsServerList: ptr::null_mut(),
            InterfaceIndex: 0,
            pQueryCompletionCallback: Some(completed),
            pQueryContext: ptr::null_mut(),
        }),
        _name: name,
        result: UnsafeCell::new(DNS_QUERY_RESULT {
            Version: DNS_QUERY_RESULTS_VERSION1,
            ..DNS_QUERY_RESULT::default()
        }),
        cancel: UnsafeCell::new(DNS_QUERY_CANCEL::default()),
        completed: AtomicBool::new(false),
        reply: Mutex::new(Some(send)),
        record_type,
        limit,
        _permit: permit,
    });

    let callback_loan = Arc::into_raw(Arc::clone(&original));
    // SAFETY: initialize the private request before giving the DNS API its
    // immutable pointer. Each side owns a strong reference even when the
    // callback runs before DnsQueryEx returns.
    let status = unsafe {
        (*original.request.get()).pQueryContext = callback_loan.cast_mut().cast();
        DnsQueryEx(
            original.request.get(),
            original.result.get(),
            original.cancel.get(),
        )
    };
    if status != DNS_REQUEST_PENDING {
        // SAFETY: synchronous completion consumes the callback loan here,
        // because the API does not invoke the callback for this return value.
        let original = unsafe { Arc::from_raw(callback_loan) };
        // SAFETY: the synchronous return has completed the original outputs.
        unsafe { original.finish(original.result.get(), Some(status)) };
    }
    Ok(Request { original, reply })
}

impl Request {
    pub(super) fn poll(&mut self, cx: &mut Context<'_>) -> Poll<Outcome> {
        Pin::new(&mut self.reply).poll(cx).map(|received| {
            received.unwrap_or_else(|_| Err(io::Error::other("Windows DNS response was lost")))
        })
    }
}

impl Drop for Request {
    #[expect(
        unsafe_code,
        reason = "Submit cancellation through the original DNS Client cancellation context"
    )]
    fn drop(&mut self) {
        if !self.original.completed.load(Ordering::Acquire) {
            // SAFETY: only a pending DnsQueryEx reaches this call. DNS Client
            // accepts a cancellation racing completion. `original` protects
            // the cancel buffer until this call returns, and the callback loan
            // protects all native storage until completion enters the callback.
            let _status = unsafe { DnsCancelQuery(self.original.cancel.get()) };
        }
    }
}

#[expect(
    unsafe_code,
    reason = "Windows returns the callback loan and the result for this original query"
)]
unsafe extern "system" fn completed(context: *const c_void, result: *mut DNS_QUERY_RESULT) {
    // SAFETY: one native pending completion returns the strong reference that
    // was lent before DnsQueryEx. It is released exactly once by this callback.
    let original = unsafe { Arc::from_raw(context.cast::<Original>()) };
    // SAFETY: the callback provides the completed original output. Fence a
    // panicking caller-supplied waker at the native callback boundary.
    let _completion = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| unsafe {
        original.finish(result, None);
    }));
}

impl Original {
    #[expect(
        unsafe_code,
        reason = "Take the completed DNS result and original native record-list allocation"
    )]
    unsafe fn finish(&self, result: *const DNS_QUERY_RESULT, status: Option<i32>) {
        self.completed.store(true, Ordering::Release);
        let sender = self
            .reply
            .lock()
            .unwrap_or_else(|error| error.into_inner())
            .take();
        // SAFETY: this is the one completion path after the OS has filled the
        // result. Any non-null record list is now exclusively owned for freeing.
        let response = unsafe { result.as_ref() }.map_or_else(
            || {
                Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "missing Windows DNS result",
                ))
            },
            |result| {
                let records = NonNull::new(result.pQueryRecords.cast()).map(Records);
                let status = status.unwrap_or(result.QueryStatus);
                if status == 0 {
                    match records {
                        Some(records) => records.answers(self.record_type, self.limit),
                        None => Ok(Vec::new()),
                    }
                } else if status == DNS_INFO_NO_RECORDS
                    || status == DNS_ERROR_RCODE_NAME_ERROR as i32
                {
                    Ok(Vec::new())
                } else {
                    Err(io::Error::from_raw_os_error(status))
                }
            },
        );
        if let Some(sender) = sender {
            let _delivered = sender.send(response);
        }
    }
}

// DnsQueryEx accepts a wide name. The generic DNS_RECORD typedef in the
// bindings uses DNS_RECORDA, but DNS Client returns the Windows wide layout.
struct Records(NonNull<DNS_RECORDW>);

impl Drop for Records {
    #[expect(
        unsafe_code,
        reason = "Release the original DNS API result list with its owning allocator"
    )]
    fn drop(&mut self) {
        // SAFETY: the completion owns this exact list and drops it once.
        unsafe { DnsFree(self.0.as_ptr().cast(), DnsFreeRecordList) };
    }
}

impl Records {
    #[expect(
        unsafe_code,
        reason = "Read only initialized native record fields and their checked data variants"
    )]
    fn answers(&self, record_type: u16, limit: usize) -> Outcome {
        let mut answers = Vec::new();
        let mut record = self.0.as_ptr();
        for _ in 0..MAX_RECORDS {
            if record.is_null() {
                return Ok(answers);
            }
            // SAFETY: DNS Client owns this linked allocation. Use raw field
            // reads because records can have a tail smaller than the union.
            let answer = unsafe { read_answer(record, record_type)? };
            if let Some(answer) = answer
                && !answers.contains(&answer)
            {
                if answers.len() == limit {
                    return Err(io::ErrorKind::OutOfMemory.into());
                }
                answers.try_reserve(1).map_err(io::Error::other)?;
                answers.push(answer);
            }
            // SAFETY: the live record header always contains its next link.
            record = unsafe { (&raw const (*record).pNext).read() };
        }
        if record.is_null() {
            Ok(answers)
        } else {
            Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "Windows DNS record list exceeds the DNS packet budget",
            ))
        }
    }
}

#[expect(
    unsafe_code,
    reason = "Read the initialized answer fields for one type-correct, length-checked native record"
)]
unsafe fn read_answer(record: *const DNS_RECORDW, record_type: u16) -> io::Result<Option<Answer>> {
    // SAFETY: the caller lent a live DNS Client record. Header fields exist
    // for every type, and each variant is read only after checking its size.
    unsafe {
        let kind = (&raw const (*record).wType).read();
        let flags = (&raw const (*record).Flags.DW).read();
        if kind != record_type || flags & DNSREC_SECTION != DNSREC_ANSWER {
            return Ok(None);
        }
        let length = usize::from((&raw const (*record).wDataLength).read());
        match kind {
            DNS_TYPE_A if length == size_of::<DNS_A_DATA>() => {
                let address = (&raw const (*record).Data.A.IpAddress).read();
                Ok(Some(Answer::V4(Ipv4Addr::from(address.to_ne_bytes()))))
            }
            DNS_TYPE_AAAA if length == size_of::<DNS_AAAA_DATA>() => {
                let bytes = (&raw const (*record).Data.AAAA.Ip6Address.IP6Byte).read();
                Ok(Answer::unscoped_ipv6(bytes))
            }
            DNS_TYPE_PTR if length == size_of::<DNS_PTR_DATAW>() => {
                let name = (&raw const (*record).Data.PTR.pNameHost).read();
                read_wide_name(name).map(|name| Some(Answer::Name(name)))
            }
            _ => Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "invalid Windows DNS answer size",
            )),
        }
    }
}

#[expect(
    unsafe_code,
    reason = "Read a DNS Client-owned UTF-16 string through its NUL with a DNS name bound"
)]
unsafe fn read_wide_name(name: *const u16) -> io::Result<String> {
    let invalid = || io::Error::new(io::ErrorKind::InvalidData, "invalid Windows DNS PTR name");
    if name.is_null() {
        return Err(invalid());
    }
    for count in 0..=MAX_NAME_LENGTH {
        // SAFETY: the original record owns a valid NUL-terminated string. No
        // unit beyond the original terminator or the configured bound is read.
        if unsafe { name.add(count).read() } != 0 {
            continue;
        }
        if count == 0 {
            return Err(invalid());
        }
        // SAFETY: we visited all of these initialized units in the live
        // original string before finding its NUL terminator.
        let units = unsafe { std::slice::from_raw_parts(name, count) };
        let mut text = String::new();
        text.try_reserve_exact(count).map_err(io::Error::other)?;
        for scalar in char::decode_utf16(units.iter().copied()) {
            let scalar = scalar.map_err(|_| invalid())?;
            if text.len() + scalar.len_utf8() > MAX_NAME_LENGTH {
                return Err(invalid());
            }
            text.try_reserve(scalar.len_utf8())
                .map_err(io::Error::other)?;
            text.push(scalar);
        }
        return Ok(text);
    }
    Err(invalid())
}

#[cfg(test)]
mod tests {
    use super::*;
    use windows_sys::Win32::NetworkManagement::Dns::{
        DNS_RECORDW_0, DNS_RECORDW_1, DNSREC_ADDITIONAL,
    };

    #[test]
    #[expect(
        unsafe_code,
        reason = "Lend fully initialized local SDK records to the native record decoder"
    )]
    #[expect(
        clippy::panic_in_result_fn,
        reason = "Assert socket-byte order, DNS section and original payload length"
    )]
    fn decodes_complete_answer_records_only() -> io::Result<()> {
        let address = [192, 0, 2, 10];
        let mut record = DNS_RECORDW {
            wType: DNS_TYPE_A,
            wDataLength: size_of::<DNS_A_DATA>() as u16,
            Flags: DNS_RECORDW_0 { DW: DNSREC_ANSWER },
            Data: DNS_RECORDW_1 {
                A: DNS_A_DATA {
                    IpAddress: u32::from_ne_bytes(address),
                },
            },
            ..DNS_RECORDW::default()
        };
        // SAFETY: the fully initialized test fixture is a live DNS A record.
        let answer = unsafe { read_answer(&raw const record, DNS_TYPE_A)? };
        assert!(answer == Some(Answer::V4(Ipv4Addr::from(address))));
        record.Flags.DW = DNSREC_ADDITIONAL;
        // SAFETY: all live record fields remain valid after changing the section.
        assert!(unsafe { read_answer(&raw const record, DNS_TYPE_A)? }.is_none());
        record.Flags.DW = DNSREC_ANSWER;
        record.wDataLength = 3;
        // SAFETY: the decoder checks the initialized length before reading data.
        assert!(unsafe { read_answer(&raw const record, DNS_TYPE_A) }.is_err());
        Ok(())
    }
}
