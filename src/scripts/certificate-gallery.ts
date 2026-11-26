function initCertificateGallery(root: HTMLElement) {
  const dialog = root.querySelector<HTMLDialogElement>('dialog');
  const dialogTitle = root.querySelector<HTMLElement>('[data-certificate-dialog-title]');
  const dialogMeta = root.querySelector<HTMLElement>('[data-certificate-dialog-meta]');
  const dialogImage = root.querySelector<HTMLImageElement>('[data-certificate-dialog-image]');
  const closeButton = root.querySelector<HTMLButtonElement>('[data-certificate-close]');
  const count = root.querySelector<HTMLElement>('[data-certificate-count]');
  const empty = root.querySelector<HTMLElement>('[data-certificate-empty]');
  const filterGroup = root.querySelector<HTMLElement>('.certificate-filters');
  if (!dialog || !dialogTitle || !dialogMeta || !dialogImage || !closeButton || !count || !empty || !filterGroup) return;

  const cards = Array.from(root.querySelectorAll<HTMLElement>('[data-certificate-card]'));
  const filters = Array.from(root.querySelectorAll<HTMLButtonElement>('[data-certificate-filter]'));
  let opener: HTMLButtonElement | null = null;
  let previousOverflow = '';
  let pointerStartedOutside = false;

  filters.forEach((button) => {
    button.addEventListener('click', () => {
      const category = button.dataset.certificateFilter;
      const visible = cards.filter((card) => category === 'All' || card.dataset.category === category);
      cards.forEach((card) => { card.hidden = !visible.includes(card); });
      filters.forEach((filter) => filter.setAttribute('aria-pressed', String(filter === button)));
      count.textContent = `${visible.length} ${visible.length === 1 ? 'certificate' : 'certificates'}`;
      empty.hidden = visible.length > 0;
    });
  });
  filterGroup.hidden = false;

  cards.forEach((card) => {
    const button = card.querySelector<HTMLButtonElement>('[data-certificate-open]');
    const image = card.querySelector<HTMLImageElement>('img');
    const title = card.querySelector('h3');
    const issuer = card.querySelector('[data-certificate-issuer]');
    const date = card.querySelector('[data-certificate-date]');
    if (!button || !image || !title || !issuer || !date) return;
    button.disabled = false;
    card.addEventListener('click', () => {
      if (dialog.open) return;
      opener = button;
      dialogTitle.textContent = title.textContent;
      dialogMeta.textContent = `${issuer.textContent} · ${date.textContent} · ${card.dataset.category}`;
      dialogImage.src = image.currentSrc || image.src;
      dialogImage.alt = image.alt;
      previousOverflow = document.body.style.overflow;
      dialog.showModal();
      document.body.style.overflow = 'hidden';
      closeButton.focus();
    });
  });

  closeButton.addEventListener('click', () => dialog.close());
  dialog.addEventListener('keydown', (event) => {
    if (event.key !== 'Tab') return;
    event.preventDefault();
    closeButton.focus();
  });
  dialog.addEventListener('close', () => {
    document.body.style.overflow = previousOverflow;
    opener?.focus({ preventScroll: true });
    dialogImage.removeAttribute('src');
  });
  const outsideDialog = (event: PointerEvent | MouseEvent) => {
    const bounds = dialog.getBoundingClientRect();
    return event.clientX < bounds.left || event.clientX > bounds.right || event.clientY < bounds.top || event.clientY > bounds.bottom;
  };
  dialog.addEventListener('pointerdown', (event) => { pointerStartedOutside = outsideDialog(event); });
  dialog.addEventListener('click', (event) => {
    if (pointerStartedOutside && outsideDialog(event)) dialog.close();
    pointerStartedOutside = false;
  });
}

document.querySelectorAll<HTMLElement>('[data-certificate-gallery]').forEach(initCertificateGallery);
