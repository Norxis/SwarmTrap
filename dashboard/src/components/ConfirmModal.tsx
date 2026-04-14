interface Props {
  open: boolean;
  title: string;
  message: string;
  confirmLabel?: string;
  onConfirm: () => void;
  onCancel: () => void;
}

export function ConfirmModal({
  open,
  title,
  message,
  confirmLabel = "Confirm",
  onConfirm,
  onCancel,
}: Props) {
  if (!open) return null;

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/60">
      <div className="bg-panel border border-border rounded-lg p-6 max-w-md w-full mx-4">
        <h3 className="text-sm font-bold mb-2">{title}</h3>
        <p className="text-xs text-muted mb-4">{message}</p>
        <div className="flex justify-end gap-2">
          <button
            className="px-3 py-1.5 text-xs rounded border border-border hover:bg-card"
            onClick={onCancel}
          >
            Cancel
          </button>
          <button
            className="px-3 py-1.5 text-xs rounded bg-danger/20 border border-danger/30 text-danger hover:bg-danger/30"
            onClick={onConfirm}
          >
            {confirmLabel}
          </button>
        </div>
      </div>
    </div>
  );
}
