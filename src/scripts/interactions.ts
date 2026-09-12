const prefersReducedMotion = window.matchMedia('(prefers-reduced-motion: reduce)').matches;

function initScrollReveal() {
  const targets = Array.from(document.querySelectorAll<HTMLElement>('.reveal'));
  if (targets.length === 0) return;

  if (prefersReducedMotion || !('IntersectionObserver' in window)) {
    targets.forEach((el) => el.classList.add('is-visible'));
    return;
  }

  const observer = new IntersectionObserver(
    (entries, obs) => {
      entries.forEach((entry) => {
        if (!entry.isIntersecting) return;
        const target = entry.target as HTMLElement;
        const delay = Number(target.dataset.revealDelay ?? 0);
        window.setTimeout(() => target.classList.add('is-visible'), delay);
        obs.unobserve(target);
      });
    },
    { threshold: 0.12, rootMargin: '0px 0px -10% 0px' }
  );

  targets.forEach((el) => observer.observe(el));
}

function copyToClipboard(text: string): Promise<void> {
  if (!navigator.clipboard) return Promise.reject(new Error('Clipboard API unavailable'));

  const timeout = new Promise<never>((_, reject) => {
    window.setTimeout(() => reject(new Error('Clipboard write timed out')), 2000);
  });

  return Promise.race([navigator.clipboard.writeText(text), timeout]);
}

function initCodeCopyButtons() {
  const blocks = Array.from(document.querySelectorAll<HTMLPreElement>('.writeup-content pre'));
  if (blocks.length === 0) return;

  blocks.forEach((pre) => {
    const code = pre.querySelector('code');
    if (!code) return;

    const button = document.createElement('button');
    button.type = 'button';
    button.className = 'copy-button';
    button.textContent = 'Copy';
    button.setAttribute('aria-label', 'Copy code to clipboard');

    button.addEventListener('click', async () => {
      try {
        await copyToClipboard(code.textContent ?? '');
        button.textContent = 'Copied';
        button.dataset.copied = 'true';
      } catch {
        button.textContent = 'Failed';
      }
      window.setTimeout(() => {
        button.textContent = 'Copy';
        delete button.dataset.copied;
      }, 1600);
    });

    pre.appendChild(button);
  });
}

document.addEventListener('DOMContentLoaded', () => {
  initScrollReveal();
  initCodeCopyButtons();
});
