(function () {
  const root = document.documentElement;
  const progress = document.querySelector('.progress');
  const menu = document.querySelector('.menu-toggle');
  const nav = document.querySelector('#menu');
  const mobile = matchMedia('(max-width: 800px)');
  const reducedMotion = matchMedia('(prefers-reduced-motion: reduce)');

  const backToTop = document.createElement('button');
  backToTop.type = 'button';
  backToTop.className = 'back-to-top';
  backToTop.setAttribute('aria-label', 'Наверх');
  backToTop.setAttribute('aria-hidden', 'true');
  backToTop.tabIndex = -1;
  backToTop.textContent = '↑';
  document.body.appendChild(backToTop);

  // Observer entries provide layout results without a synchronous geometry read.
  let pageHeight = 0;
  let needsFallbackMeasure = !('ResizeObserver' in window);
  let frame = 0;
  let previousProgress = -1;
  let topButtonVisible = false;

  function updateScroll() {
    frame = 0;
    const y = window.scrollY;
    const viewportHeight = window.innerHeight;
    if (needsFallbackMeasure) {
      pageHeight = root.scrollHeight;
      needsFallbackMeasure = false;
    }
    const maxScroll = Math.max(0, pageHeight - viewportHeight);
    const fraction = maxScroll ? Math.max(0, Math.min(1, y / maxScroll)) : 0;
    const showTopButton = y > 600;

    // Keep reads above and coalesce DOM writes into one animation frame.
    if (progress && fraction !== previousProgress) {
      progress.style.setProperty('--p', fraction);
      previousProgress = fraction;
    }
    if (showTopButton !== topButtonVisible) {
      backToTop.classList.toggle('is-visible', showTopButton);
      backToTop.setAttribute('aria-hidden', String(!showTopButton));
      backToTop.tabIndex = showTopButton ? 0 : -1;
      topButtonVisible = showTopButton;
    }
  }

  function scheduleScrollUpdate() {
    if (!frame) frame = requestAnimationFrame(updateScroll);
  }

  if ('ResizeObserver' in window) {
    const heights = new Map();
    const sizeObserver = new ResizeObserver(entries => {
      entries.forEach(entry => heights.set(entry.target, entry.contentRect.height));
      pageHeight = Math.max(0, ...heights.values());
      scheduleScrollUpdate();
    });
    sizeObserver.observe(root);
    sizeObserver.observe(document.body);
  }
  addEventListener('scroll', scheduleScrollUpdate, { passive: true });
  addEventListener('resize', () => {
    if (!('ResizeObserver' in window)) needsFallbackMeasure = true;
    scheduleScrollUpdate();
  }, { passive: true });
  addEventListener('load', () => {
    if (!('ResizeObserver' in window)) needsFallbackMeasure = true;
    scheduleScrollUpdate();
  }, { once: true });
  scheduleScrollUpdate();

  function focusContent(target) {
    if (!target) return;
    if (!target.hasAttribute('tabindex')) target.setAttribute('tabindex', '-1');
    target.focus({ preventScroll: true });
  }

  function setMenu(open, restoreFocus = false) {
    if (!menu || !nav) return;
    const expanded = mobile.matches && open;
    if (restoreFocus) menu.focus({ preventScroll: true });
    menu.setAttribute('aria-expanded', String(expanded));
    nav.classList.toggle('is-open', expanded);
    nav.inert = mobile.matches && !expanded;
    if (mobile.matches) nav.setAttribute('aria-hidden', String(!expanded));
    else nav.removeAttribute('aria-hidden');
  }

  menu?.addEventListener('click', () => {
    setMenu(menu.getAttribute('aria-expanded') !== 'true');
  });
  nav?.addEventListener('click', event => {
    const link = event.target.closest('a');
    if (!link || !nav.contains(link)) return;
    const wasOpen = mobile.matches && menu?.getAttribute('aria-expanded') === 'true';
    const isLocalAnchor = !event.defaultPrevented && !event.ctrlKey && !event.metaKey &&
      !event.shiftKey && !event.altKey && link.origin === location.origin &&
      link.pathname === location.pathname && link.hash;
    let target = null;
    if (isLocalAnchor) {
      try { target = document.getElementById(decodeURIComponent(link.hash.slice(1))); }
      catch (_) { /* An invalid fragment keeps the browser's normal link behavior. */ }
    }
    setMenu(false, wasOpen && nav.contains(document.activeElement));
    // Native anchor navigation owns scrolling; move keyboard focus after it starts.
    if (wasOpen && target) requestAnimationFrame(() => focusContent(target));
  });
  addEventListener('keydown', event => {
    if (event.key === 'Escape' && menu?.getAttribute('aria-expanded') === 'true') {
      setMenu(false, true);
    }
  });
  function updateMenuBreakpoint() {
    const active = document.activeElement;
    setMenu(false, mobile.matches && !!nav?.contains(active));
    if (!mobile.matches && active === menu) nav?.querySelector('a')?.focus({ preventScroll: true });
  }
  if (mobile.addEventListener) mobile.addEventListener('change', updateMenuBreakpoint);
  else mobile.addListener(updateMenuBreakpoint);
  setMenu(false);

  backToTop.addEventListener('click', () => {
    focusContent(document.querySelector('main'));
    window.scrollTo({ top: 0, behavior: reducedMotion.matches ? 'auto' : 'smooth' });
  });

  const items = document.querySelectorAll('.reveal');
  let revealObserver;
  function reveal(item) {
    item.classList.add('is-visible');
    revealObserver?.unobserve(item);
  }
  // A keyboard user must never land inside a still-transparent reveal section.
  document.addEventListener('focusin', event => {
    let node = event.target;
    while (node && node !== root) {
      if (node.classList?.contains('reveal')) reveal(node);
      node = node.parentElement;
    }
  });
  if (!('IntersectionObserver' in window) || reducedMotion.matches) {
    items.forEach(reveal);
  } else {
    revealObserver = new IntersectionObserver(entries => {
      entries.forEach(entry => {
        if (entry.isIntersecting) reveal(entry.target);
      });
    }, { threshold: .08, rootMargin: '0px 0px -5%' });
    root.classList.add('motion-ready');
    items.forEach(item => revealObserver.observe(item));
  }
  function updateMotionPreference() {
    if (reducedMotion.matches) {
      items.forEach(reveal);
      revealObserver?.disconnect();
    }
  }
  if (reducedMotion.addEventListener) reducedMotion.addEventListener('change', updateMotionPreference);
  else reducedMotion.addListener(updateMotionPreference);
})();
