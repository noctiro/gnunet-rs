#include "wrapper.h"

void gnunet_wfp_complete_request(PIRP irp, CCHAR priority_boost) {
    IoCompleteRequest(irp, priority_boost);
}
void gnunet_wfp_mark_irp_pending(PIRP irp) { IoMarkIrpPending(irp); }
PIO_STACK_LOCATION gnunet_wfp_current_irp_stack(PIRP irp) {
    return IoGetCurrentIrpStackLocation(irp);
}
void gnunet_wfp_initialize_spin_lock(PKSPIN_LOCK lock) { KeInitializeSpinLock(lock); }
KIRQL gnunet_wfp_acquire_spin_lock(PKSPIN_LOCK lock) {
    KIRQL old_irql;
    KeAcquireSpinLock(lock, &old_irql);
    return old_irql;
}
void gnunet_wfp_release_spin_lock(PKSPIN_LOCK lock, KIRQL old_irql) {
    KeReleaseSpinLock(lock, old_irql);
}
KIRQL gnunet_wfp_current_irql(void) { return KeGetCurrentIrql(); }

NTSTATUS gnunet_wfp_reference_user_event(PIRP irp, HANDLE handle, PKEVENT *event) {
    PVOID object = NULL;
    if (irp->RequestorMode != UserMode ||
        IoGetRequestorProcess(irp) != PsGetCurrentProcess()) {
        return STATUS_ACCESS_DENIED;
    }
    NTSTATUS status = ObReferenceObjectByHandle(
        handle, EVENT_MODIFY_STATE, *ExEventObjectType, UserMode, &object, NULL);
    if (NT_SUCCESS(status)) {
        *event = (PKEVENT)object;
    }
    return status;
}
void gnunet_wfp_release_event(PKEVENT event) { ObDereferenceObject(event); }

NTSTATUS gnunet_wfp_retain_user_socket(PIRP irp, HANDLE handle, PHANDLE retained) {
    const ACCESS_MASK access = FILE_READ_DATA | FILE_WRITE_DATA;
    PVOID object = NULL;
    if (irp->RequestorMode != UserMode ||
        IoGetRequestorProcess(irp) != PsGetCurrentProcess()) {
        return STATUS_ACCESS_DENIED;
    }
    NTSTATUS status = ObReferenceObjectByHandle(
        handle, access, *IoFileObjectType, UserMode, &object, NULL);
    if (!NT_SUCCESS(status)) {
        return status;
    }
    PFILE_OBJECT file = (PFILE_OBJECT)object;
    if ((file->Flags & FO_HANDLE_CREATED) == 0) {
        ObDereferenceObject(object);
        return STATUS_INVALID_HANDLE;
    }
    status = ObOpenObjectByPointer(
        file, OBJ_KERNEL_HANDLE | OBJ_FORCE_ACCESS_CHECK, NULL,
        access, *IoFileObjectType, KernelMode, retained);
    ObDereferenceObject(object);
    return status;
}

NTSTATUS gnunet_wfp_release_socket(HANDLE handle) {
    return ObCloseHandle(handle, KernelMode);
}

NTSTATUS gnunet_wfp_nbl_status(const NET_BUFFER_LIST *list) {
    return NET_BUFFER_LIST_STATUS(list);
}
NET_BUFFER_LIST *gnunet_wfp_nbl_next(const NET_BUFFER_LIST *list) {
    return NET_BUFFER_LIST_NEXT_NBL(list);
}
NET_BUFFER *gnunet_wfp_nbl_first_nb(const NET_BUFFER_LIST *list) {
    return NET_BUFFER_LIST_FIRST_NB(list);
}
NET_BUFFER *gnunet_wfp_nb_next(const NET_BUFFER *buffer) { return NET_BUFFER_NEXT_NB(buffer); }
ULONG gnunet_wfp_nb_data_length(const NET_BUFFER *buffer) { return NET_BUFFER_DATA_LENGTH(buffer); }
ULONG gnunet_wfp_nb_data_offset(const NET_BUFFER *buffer) { return NET_BUFFER_DATA_OFFSET(buffer); }
PMDL gnunet_wfp_nb_current_mdl(const NET_BUFFER *buffer) { return NET_BUFFER_CURRENT_MDL(buffer); }
ULONG gnunet_wfp_nb_current_mdl_offset(const NET_BUFFER *buffer) {
    return NET_BUFFER_CURRENT_MDL_OFFSET(buffer);
}
