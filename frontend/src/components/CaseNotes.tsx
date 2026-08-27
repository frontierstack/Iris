/** Case notes as a chat-style feed: post timestamped markdown entries, edit them, attach screenshots, link evidence. */
import { useMutation, useQueryClient } from '@tanstack/react-query';
import type { ClipboardEvent, DragEvent, KeyboardEvent, ReactNode, SVGProps } from 'react';
import { useEffect, useMemo, useRef, useState } from 'react';
import { useNavigate } from 'react-router-dom';
import { api } from '../api/client';
import type { CaseNote, NoteRef } from '../api/types';
import { qk, useNotes } from '../hooks/queries';
import { useArrivals, useTypewriter } from '../hooks/useArrivals';
import { useToast } from '../hooks/useToast';
import { cx, fmtRelative, fmtTs, initials } from '../utils/format';
import { renderMarkdown } from '../utils/markdown';
import { Icon } from './icons';
import { ConfirmDialog, EmptyState } from './ui';

/* Toolbar glyphs — same geometry as components/icons.tsx (16×16 box, 1.5 stroke, 12px live area). */
type P = SVGProps<SVGSVGElement>;
const g = { width: 14, height: 14, viewBox: '0 0 16 16', fill: 'none', stroke: 'currentColor', strokeWidth: 1.5, strokeLinecap: 'round', strokeLinejoin: 'round' } as const;
const Mk = {
  Bullets: (p: P) => (
    <svg {...g} {...p}><path d="M6 4h7.5M6 8h7.5M6 12h7.5" /><circle cx="3" cy="4" r=".9" fill="currentColor" stroke="none" /><circle cx="3" cy="8" r=".9" fill="currentColor" stroke="none" /><circle cx="3" cy="12" r=".9" fill="currentColor" stroke="none" /></svg>
  ),
  Numbers: (p: P) => (
    <svg {...g} {...p}><path d="M6.5 4h7M6.5 8h7M6.5 12h7" /><path d="M2.2 2.9 3.2 2.4v2.9M2.2 6.7h1.7L2.2 9.3h1.8M2.2 10.7h1.7v1.2H2.4v1.2h1.5" /></svg>
  ),
  Table: (p: P) => (
    <svg {...g} {...p}><rect x="2.3" y="3.3" width="11.4" height="9.4" rx="1" /><path d="M2.3 6.6h11.4M6.4 6.6v6.1M10.1 6.6v6.1" /></svg>
  ),
  Link: (p: P) => (
    <svg {...g} {...p}><path d="M6.6 9.4a2.6 2.6 0 0 1 0-3.7l2-2a2.6 2.6 0 0 1 3.7 3.7l-.9.9" /><path d="M9.4 6.6a2.6 2.6 0 0 1 0 3.7l-2 2a2.6 2.6 0 0 1-3.7-3.7l.9-.9" /></svg>
  ),
  Image: (p: P) => (
    <svg {...g} {...p}><rect x="2.3" y="3.3" width="11.4" height="9.4" rx="1" /><circle cx="5.9" cy="6.5" r="1.05" /><path d="m3 11.4 3.1-2.8 2.4 2.1 2-1.7 2.5 2.4" /></svg>
  ),
};

/* The formats the attachment endpoint accepts, by extension — used when the OS hands over a file with
   no MIME type at all (common for .webp/.bmp on Windows), which used to be dropped on the floor. */
const IMG_TYPES: Record<string, string> = {
  png: 'image/png', jpg: 'image/jpeg', jpeg: 'image/jpeg', gif: 'image/gif', webp: 'image/webp', bmp: 'image/bmp',
};

/** The file as an image upload, or null if it is not one. Re-wraps a type-less file so multipart carries a type. */
function asImage(f: File): File | null {
  if (f.type.startsWith('image/')) return f;
  const type = IMG_TYPES[(f.name.split('.').pop() ?? '').toLowerCase()];
  return type ? new File([f], f.name, { type }) : null;
}

/** Image files out of a clipboard/drag payload.
 *  `.files` is empty for a pasted bitmap in some browsers (Firefox delivers it only through `.items`),
 *  which made Ctrl+V of a screenshot look like nothing happened at all — so fall back to `.items`. */
function imageFiles(data: DataTransfer | null | undefined): File[] {
  if (!data) return [];
  const out = Array.from(data.files ?? []).map(asImage).filter((f): f is File => f !== null);
  if (out.length) return out;
  for (const it of Array.from(data.items ?? [])) {
    if (it.kind !== 'file') continue;
    const f = it.getAsFile();
    const img = f && asImage(f);
    if (img) out.push(img);
  }
  return out;
}

/** Image markdown inside a draft, so the editor can show the picture rather than only the token.
 *  Attaching a screenshot writes `![name](/api/cases/<id>/attachments/<file>)` into the textarea — the
 *  posted note renders it as an <img>, but in Write mode that is a line of literal markdown, which reads
 *  exactly like "the image did not render". The strip below is the missing feedback. */
const DRAFT_IMG = /!\[([^\]]*)\]\((\/api\/cases\/[^)\s]+)\)/g;

function draftImages(src: string): { alt: string; url: string }[] {
  const out: { alt: string; url: string }[] = [];
  for (const m of (src ?? '').matchAll(DRAFT_IMG)) out.push({ alt: m[1] ?? '', url: m[2] ?? '' });
  return out;
}

/** A note's linked evidence, rendered as chips that navigate to the thing they point at. */
function RefChips({ refs }: { refs: NoteRef[] }) {
  const nav = useNavigate();
  if (!refs.length) return null;
  const go = (r: NoteRef) => {
    if (r.kind === 'event') nav(`/events/${encodeURIComponent(r.value)}`);
    else if (r.kind === 'search') nav(`/search?q=${encodeURIComponent(r.value)}`);
    else if (r.kind === 'entity') nav(`/graph?entity=${encodeURIComponent(r.value)}`);
    else if (r.kind === 'cluster') nav('/cases');
    else if (r.kind === 'source') nav('/ingest');
  };
  return (
    <div className="note__refs">
      {refs.map((r, i) => (
        <button key={`${r.kind}:${r.value}:${i}`} className="note-ref" onClick={() => go(r)} title={`${r.kind}: ${r.value}`}>
          <span className="note-ref__kind">{r.kind}</span>
          <span className="note-ref__label ellipsis">{r.label || r.value}</span>
        </button>
      ))}
    </div>
  );
}

type EditorProps = {
  caseId: string;
  value: string;
  onChange: (v: string) => void;
  rows?: number;
  placeholder?: string;
  autoFocus?: boolean;
  onKeyDown?: (e: KeyboardEvent<HTMLTextAreaElement>) => void;
};

/** Textarea + markdown toolbar + Write/Preview, with paste / drop / picker image attachments. */
function MarkdownEditor({ caseId, value, onChange, rows = 3, placeholder, autoFocus, onKeyDown }: EditorProps) {
  const toast = useToast();
  const ta = useRef<HTMLTextAreaElement>(null);
  const picker = useRef<HTMLInputElement>(null);
  const [preview, setPreview] = useState(false);
  const [dropping, setDropping] = useState(false);
  const [busy, setBusy] = useState(false);
  const shots = draftImages(value);

  /** Replace the current selection, then restore it inside the inserted markers. */
  const surround = (before: string, after: string, sample: string) => {
    const el = ta.current;
    if (!el) return;
    const s = el.selectionStart, e = el.selectionEnd;
    const sel = el.value.slice(s, e) || sample;
    onChange(el.value.slice(0, s) + before + sel + after + el.value.slice(e));
    requestAnimationFrame(() => {
      el.focus();
      el.setSelectionRange(s + before.length, s + before.length + sel.length);
    });
  };

  /** Prefix every selected line (lists). */
  const prefixLines = (mark: (i: number) => string) => {
    const el = ta.current;
    if (!el) return;
    const v = el.value;
    const start = v.lastIndexOf('\n', Math.max(0, el.selectionStart - 1)) + 1;
    const endRaw = v.indexOf('\n', el.selectionEnd);
    const end = endRaw === -1 ? v.length : endRaw;
    const block = (v.slice(start, end) || 'item').split('\n').map((l, i) => mark(i) + l).join('\n');
    onChange(v.slice(0, start) + block + v.slice(end));
    requestAnimationFrame(() => { el.focus(); el.setSelectionRange(start, start + block.length); });
  };

  /** Drop a block of markdown in at the cursor, on its own lines. */
  const insertBlock = (block: string) => {
    const el = ta.current;
    if (!el) {
      // No textarea to insert into (Preview mode hides it). Appending instead of bailing out is the
      // difference between the screenshot showing up and the upload silently going nowhere.
      onChange(value + (!value || value.endsWith('\n') ? '' : '\n') + block + '\n');
      return;
    }
    const v = el.value;
    const at = el.selectionStart;
    const lead = at === 0 || v.slice(0, at).endsWith('\n') ? '' : '\n';
    const next = v.slice(0, at) + lead + block + '\n' + v.slice(el.selectionEnd);
    onChange(next);
    const caret = at + lead.length + block.length + 1;
    requestAnimationFrame(() => { el.focus(); el.setSelectionRange(caret, caret); });
  };

  const attach = async (files: File[]) => {
    const images = files.map(asImage).filter((f): f is File => f !== null);
    if (!images.length) {
      if (files.length) toast.error('That file is not an image', 'PNG, JPEG, GIF, WEBP or BMP only');
      return;
    }
    setBusy(true);
    try {
      const refs: string[] = [];
      for (const f of images) {
        const a = await api.uploadAttachment(caseId, f);
        refs.push(`![${a.name.replace(/[[\]()]/g, '')}](${a.url})`);
      }
      insertBlock(refs.join('\n'));
    } catch (err) {
      toast.error('Could not attach the image', err);
    } finally {
      setBusy(false);
    }
  };

  const onPaste = (e: ClipboardEvent<HTMLTextAreaElement>) => {
    const files = imageFiles(e.clipboardData);
    if (!files.length) return;
    e.preventDefault();
    void attach(files);
  };
  const onDrop = (e: DragEvent<HTMLDivElement>) => {
    const files = imageFiles(e.dataTransfer);
    setDropping(false);
    if (!files.length) return;
    e.preventDefault();
    void attach(files);
  };

  const tool = (label: string, title: string, run: () => void, node?: ReactNode) => (
    <button type="button" className="md-tool" title={title} aria-label={title} onMouseDown={(e) => e.preventDefault()} onClick={run}>
      {node ?? <span className={`md-tool__glyph md-tool__glyph--${label}`}>{label === 'bold' ? 'B' : label === 'italic' ? 'I' : '‹›'}</span>}
    </button>
  );

  return (
    <div className={cx('md-editor', dropping && 'md-editor--drop')}
      onDragOver={(e) => { if (e.dataTransfer?.types?.includes('Files')) { e.preventDefault(); setDropping(true); } }}
      onDragLeave={() => setDropping(false)}
      onDrop={onDrop}
    >
      <div className="md-toolbar">
        {tool('bold', 'Bold', () => surround('**', '**', 'bold'))}
        {tool('italic', 'Italic', () => surround('*', '*', 'italic'))}
        {tool('code', 'Code', () => surround('`', '`', 'code'))}
        <span className="md-toolbar__sep" />
        {tool('ul', 'Bullet list', () => prefixLines(() => '- '), <Mk.Bullets />)}
        {tool('ol', 'Numbered list', () => prefixLines((i) => `${i + 1}. `), <Mk.Numbers />)}
        {tool('table', 'Table', () => insertBlock('| Field | Value |\n| --- | --- |\n|  |  |'), <Mk.Table />)}
        {tool('link', 'Link', () => surround('[', '](https://)', 'text'), <Mk.Link />)}
        {tool('image', 'Attach an image', () => picker.current?.click(), <Mk.Image />)}
        <span className="md-toolbar__spacer" />
        <div className="md-modes" role="group" aria-label="Editor mode">
          <button type="button" className={cx('md-mode', !preview && 'is-on')} onClick={() => setPreview(false)}>Write</button>
          <button type="button" className={cx('md-mode', preview && 'is-on')} onClick={() => setPreview(true)}>Preview</button>
        </div>
      </div>
      {preview ? (
        <div className="md md-preview">
          {value.trim() ? renderMarkdown(value) : <p className="md-preview__empty">Nothing to preview yet.</p>}
        </div>
      ) : (
        <textarea
          ref={ta}
          className="composer__input md-input"
          rows={rows}
          value={value}
          autoFocus={autoFocus}
          onChange={(e) => onChange(e.target.value)}
          onKeyDown={onKeyDown}
          onPaste={onPaste}
          placeholder={placeholder}
        />
      )}
      {!preview && shots.length > 0 && (
        <div className="md-shots" aria-label="Attached images">
          {shots.map((s, i) => (
            <figure key={`${s.url}-${i}`} className="md-shot">
              <img src={s.url} alt={s.alt} loading="lazy" />
              <figcaption className="ellipsis" title={s.alt}>{s.alt || 'image'}</figcaption>
            </figure>
          ))}
        </div>
      )}
      <input ref={picker} type="file" accept="image/png,image/jpeg,image/gif,image/webp,image/bmp" multiple hidden
        onChange={(e) => { void attach(Array.from(e.target.files ?? [])); e.target.value = ''; }} />
      {busy && <div className="md-editor__busy"><span className="btn__spinner" />Uploading image…</div>}
      {dropping && <div className="md-editor__hint">Drop an image to attach it</div>}
    </div>
  );
}

function Composer({ caseId, pending, onPosted }: { caseId: string; pending: NoteRef[]; onPosted?: () => void }) {
  const qc = useQueryClient();
  const toast = useToast();
  const [text, setText] = useState('');
  const [refs, setRefs] = useState<NoteRef[]>(pending);
  useEffect(() => { setRefs(pending); }, [pending]);

  const post = useMutation({
    mutationFn: () => api.addNote(caseId, { text: text.trim(), refs }),
    onSuccess: () => {
      setText('');
      setRefs([]);
      void qc.invalidateQueries({ queryKey: qk.notes(caseId) });
      void qc.invalidateQueries({ queryKey: ['case-detail'] });
      void qc.invalidateQueries({ queryKey: qk.report });
      onPosted?.();
    },
    onError: (e) => toast.error('Could not post the note', e),
  });

  const canPost = (text.trim().length > 0 || refs.length > 0) && !post.isPending;
  return (
    <div className="composer">
      {refs.length > 0 && (
        <div className="composer__refs">
          {refs.map((r, i) => (
            <span key={`${r.kind}:${r.value}:${i}`} className="note-ref note-ref--draft">
              <span className="note-ref__kind">{r.kind}</span>
              <span className="note-ref__label ellipsis">{r.label || r.value}</span>
              <button onClick={() => setRefs((x) => x.filter((_, j) => j !== i))} aria-label="Remove link">×</button>
            </span>
          ))}
        </div>
      )}
      <MarkdownEditor
        caseId={caseId}
        value={text}
        onChange={setText}
        rows={3}
        placeholder="Write a note…  markdown, paste or drop a screenshot  (Ctrl+Enter to post)"
        onKeyDown={(e) => {
          // Ctrl/⌘+Enter posts — plain Enter is a new line now that notes are multi-line markdown
          if (e.key === 'Enter' && (e.ctrlKey || e.metaKey)) { e.preventDefault(); if (canPost) post.mutate(); }
        }}
      />
      <div className="composer__actions">
        <span className="field__hint">{refs.length > 0 ? `${refs.length} link${refs.length === 1 ? '' : 's'} attached` : 'Markdown supported — link evidence from Search or an event'}</span>
        <button className="btn btn--sm btn--accent" onClick={() => post.mutate()} disabled={!canPost}>
          {post.isPending && <span className="btn__spinner" />}Post
        </button>
      </div>
    </div>
  );
}

function NoteRow({ caseId, note, arriving = false }: { caseId: string; note: CaseNote; arriving?: boolean }) {
  const qc = useQueryClient();
  // A note that ARRIVED while the feed was on screen (the assistant just wrote it) fades in and is
  // revealed as if being written; the initial load and an edit paint at once. hooks/useArrivals.ts.
  const shown = useTypewriter(note.text, arriving);
  const toast = useToast();
  const [editing, setEditing] = useState(false);
  const [draft, setDraft] = useState(note.text);
  const [confirmDel, setConfirmDel] = useState(false);
  useEffect(() => { setDraft(note.text); }, [note.text]);

  const invalidate = () => {
    void qc.invalidateQueries({ queryKey: qk.notes(caseId) });
    void qc.invalidateQueries({ queryKey: ['case-detail'] });
    void qc.invalidateQueries({ queryKey: qk.report });
  };
  const save = useMutation({
    mutationFn: () => api.updateNote(caseId, note.id, { text: draft }),
    onSuccess: () => { setEditing(false); invalidate(); },
    onError: (e) => toast.error('Could not save the note', e),
  });
  const del = useMutation({
    mutationFn: () => api.deleteNote(caseId, note.id),
    onSuccess: () => { setConfirmDel(false); invalidate(); },
    onError: (e) => toast.error('Could not delete the note', e),
  });

  return (
    <div className={cx('note', arriving && 'note--arriving')}>
      <div className="note__avatar" aria-hidden>{initials(note.author) || '—'}</div>
      <div className="note__body">
        <div className="note__head">
          <span className="note__author">{note.author || 'analyst'}</span>
          {/* The FULL timestamp, date included. "2d ago" is unusable in an incident write-up: a note has
              to say when it was written, and a case is read weeks later and correlated against logs in
              UTC. The relative form is the hover, not the label. */}
          <span className="note__time" title={fmtRelative(note.createdAt)}>{fmtTs(note.createdAt)} UTC</span>
          {note.updatedAt && (
            <span className="note__edited" title={fmtRelative(note.updatedAt)}>(edited {fmtTs(note.updatedAt)} UTC)</span>
          )}
          <span className="note__tools">
            <button onClick={() => setEditing((v) => !v)} aria-label="Edit note">edit</button>
            <button onClick={() => setConfirmDel(true)} aria-label="Delete note">delete</button>
          </span>
        </div>
        {editing ? (
          <div className="note__edit">
            <MarkdownEditor
              caseId={caseId}
              value={draft}
              onChange={setDraft}
              rows={4}
              onKeyDown={(e) => { if (e.key === 'Enter' && (e.ctrlKey || e.metaKey)) { e.preventDefault(); save.mutate(); }
                                  if (e.key === 'Escape') { setDraft(note.text); setEditing(false); } }}
            />
            <div className="note__edit-actions">
              <button className="btn btn--sm btn--ghost" onClick={() => { setDraft(note.text); setEditing(false); }}>Cancel</button>
              <button className="btn btn--sm btn--accent" onClick={() => save.mutate()} disabled={save.isPending || !draft.trim()}>
                {save.isPending && <span className="btn__spinner" />}Save
              </button>
            </div>
          </div>
        ) : (
          <div className="note__text md">{renderMarkdown(shown)}</div>
        )}
        <RefChips refs={note.refs} />
      </div>
      <ConfirmDialog
        open={confirmDel}
        title="Delete note"
        danger
        confirmLabel="Delete"
        busy={del.isPending}
        text={<>Delete this note? This cannot be undone.</>}
        onConfirm={() => del.mutate()}
        onCancel={() => setConfirmDel(false)}
      />
    </div>
  );
}

/**
 * NEWEST FIRST. The investigation log is read to find out what happened LAST — during an incident,
 * and again weeks later — and an append-ordered feed puts that at the bottom of an arbitrarily long
 * scroll. Sorting is on the note's OWN `createdAt`, not on the position the API returned it in, so a
 * note posted while the analyst is looking lands at the top the moment the query refetches, whatever
 * order the server serialises. `createdAt` is the CREATION time (an edit sets `updatedAt` instead),
 * so editing a note in place never moves it — the log stays a chronology, not a recently-touched list.
 *
 * The order is a display decision and lives here alone: `cases.add_note` still appends, the report,
 * the export and `restore_note` all keep reading the file in the order it was written.
 */
function newestFirst(notes: CaseNote[]): CaseNote[] {
  return [...notes].sort((a, b) => {
    const ta = Date.parse(a.createdAt);
    const tb = Date.parse(b.createdAt);
    // Two notes can share a timestamp (the assistant writes several in one run, and it is ISO to the
    // second): fall back to the stored order, reversed, so the tie is stable and still newest-first.
    if (ta === tb || Number.isNaN(ta) || Number.isNaN(tb)) return notes.indexOf(b) - notes.indexOf(a);
    return tb - ta;
  });
}

export function CaseNotesFeed({ caseId, pendingRefs = [], onPosted }: { caseId: string; pendingRefs?: NoteRef[]; onPosted?: () => void }) {
  const notes = useNotes(caseId);
  const list = useMemo(() => newestFirst(notes.data ?? []), [notes.data]);
  const arrivals = useArrivals(useMemo(() => list.map((n) => n.id), [list]), notes.data !== undefined);
  return (
    <div className="notes">
      {/* The composer leads the feed because the feed is newest-first: what you post appears in the
          row directly below the box you typed it in. Leaving it at the bottom would put a new entry
          a whole scroll away from the control that created it. */}
      <Composer caseId={caseId} pending={pendingRefs} onPosted={onPosted} />
      {list.length === 0 && !notes.isLoading && (
        <EmptyState inline title="No notes yet"
          body="Post what you find as you go — each entry is timestamped, editable, takes markdown and screenshots, and can link back to the events behind it. The newest entry stays at the top." />
      )}
      <div className="notes__feed">
        {list.map((n) => <NoteRow key={n.id} caseId={caseId} note={n} arriving={arrivals.has(n.id)} />)}
      </div>
    </div>
  );
}

/** "Add a note about this" — used from Search rows and Event detail. */
export function NoteAboutButton({ caseId, refToAttach, compact }: { caseId: string; refToAttach: NoteRef; compact?: boolean }) {
  const qc = useQueryClient();
  const toast = useToast();
  const [open, setOpen] = useState(false);
  const [text, setText] = useState('');
  const post = useMutation({
    mutationFn: () => api.addNote(caseId, { text: text.trim(), refs: [refToAttach] }),
    onSuccess: () => {
      setText('');
      setOpen(false);
      toast.success('Note added', refToAttach.label || refToAttach.value);
      void qc.invalidateQueries({ queryKey: qk.notes(caseId) });
      void qc.invalidateQueries({ queryKey: ['case-detail'] });
    },
    onError: (e) => toast.error('Could not post the note', e),
  });

  return (
    <>
      <button
        className={cx(compact ? 'incase-btn' : 'btn btn--sm')}
        onClick={(e) => { e.stopPropagation(); setOpen(true); }}
        title="Write a case note linked to this"
        aria-label="Add a note about this"
      >
        <Icon.Note />{!compact && ' Note'}
      </button>
      <ConfirmDialog
        open={open}
        title="Add a case note"
        confirmLabel="Post note"
        busy={post.isPending}
        text={
          <div className="note-dialog">
            <div className="note-ref note-ref--draft">
              <span className="note-ref__kind">{refToAttach.kind}</span>
              <span className="note-ref__label ellipsis">{refToAttach.label || refToAttach.value}</span>
            </div>
            <MarkdownEditor caseId={caseId} value={text} onChange={setText} rows={4} autoFocus
              placeholder="What does this show?" />
          </div>
        }
        onConfirm={() => post.mutate()}
        onCancel={() => { setOpen(false); setText(''); }}
      />
    </>
  );
}
