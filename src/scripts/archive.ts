// Client-side search, section filter and pagination for the blog archive.
// State lives in the URL (?q=&section=&page=) so results can be linked and survive reload.
const PAGE_SIZE = 12;

const rows = Array.from(document.querySelectorAll<HTMLElement>('[data-archive] [data-post]'));
const input = document.querySelector<HTMLInputElement>('[data-archive-search]');
const pills = Array.from(document.querySelectorAll<HTMLButtonElement>('[data-archive-filter]'));
const empty = document.querySelector<HTMLElement>('[data-archive-empty]');
const count = document.querySelector<HTMLElement>('[data-archive-count]');
const pager = document.querySelector<HTMLElement>('[data-archive-pager]');
const pageLabel = document.querySelector<HTMLElement>('[data-archive-page]');
const prev = document.querySelector<HTMLButtonElement>('[data-archive-prev]');
const next = document.querySelector<HTMLButtonElement>('[data-archive-next]');

const params = new URLSearchParams(window.location.search);
const sections = new Set(pills.map((pill) => pill.dataset.archiveFilter));
const state = {
  q: params.get('q') ?? '',
  section: sections.has(params.get('section') ?? '') ? (params.get('section') as string) : 'all',
  page: Math.max(1, Number.parseInt(params.get('page') ?? '1', 10) || 1)
};

function render() {
  const terms = state.q.toLowerCase().split(/\s+/).filter(Boolean);
  const matches = rows.filter((row) => {
    if (state.section !== 'all' && row.dataset.section !== state.section) return false;
    const haystack = row.dataset.search ?? '';
    return terms.every((term) => haystack.includes(term));
  });

  const pages = Math.max(1, Math.ceil(matches.length / PAGE_SIZE));
  state.page = Math.min(state.page, pages);
  const start = (state.page - 1) * PAGE_SIZE;
  const visible = new Set(matches.slice(start, start + PAGE_SIZE));
  rows.forEach((row) => {
    row.hidden = !visible.has(row);
  });

  pills.forEach((pill) => pill.setAttribute('aria-pressed', String(pill.dataset.archiveFilter === state.section)));
  if (empty) empty.hidden = matches.length > 0;
  if (count) count.textContent = `${matches.length} of ${rows.length} posts`;
  if (pager) pager.hidden = pages <= 1;
  if (pageLabel) pageLabel.textContent = `Page ${state.page} of ${pages}`;
  if (prev) prev.disabled = state.page <= 1;
  if (next) next.disabled = state.page >= pages;

  const url = new URLSearchParams();
  if (state.q) url.set('q', state.q);
  if (state.section !== 'all') url.set('section', state.section);
  if (state.page > 1) url.set('page', String(state.page));
  const query = url.toString();
  window.history.replaceState(null, '', query ? `?${query}` : window.location.pathname);
}

const turnPage = (delta: number) => {
  state.page += delta;
  render();
  document.querySelector('[data-archive]')?.scrollIntoView({ block: 'start' });
};

if (input) {
  input.value = state.q;
  input.addEventListener('input', () => {
    state.q = input.value.trim();
    state.page = 1;
    render();
  });
}

pills.forEach((pill) =>
  pill.addEventListener('click', () => {
    state.section = pill.dataset.archiveFilter ?? 'all';
    state.page = 1;
    render();
  })
);

document.querySelector('[data-archive-reset]')?.addEventListener('click', () => {
  state.q = '';
  state.section = 'all';
  state.page = 1;
  if (input) input.value = '';
  render();
  input?.focus();
});

prev?.addEventListener('click', () => turnPage(-1));
next?.addEventListener('click', () => turnPage(1));

render();
