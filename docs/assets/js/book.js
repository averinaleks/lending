/* Book Psychoanalytic Theme — interactions */
(function(){
  const root = document.documentElement;
  const progress = document.querySelector('.progress');
  const themeBtn = document.querySelector('[data-toggle-theme]');
  const tocLinks = document.querySelectorAll('.toc a');
  const prefersDark = window.matchMedia && window.matchMedia('(prefers-color-scheme: dark)').matches;
  const savedTheme = localStorage.getItem('theme');
  if (savedTheme === 'dark' || (!savedTheme && prefersDark)) {
    document.documentElement.classList.add('theme-dark');
  }
  function updateProgress(){
    const scrollTop = window.scrollY || document.documentElement.scrollTop;
    const docHeight = document.documentElement.scrollHeight - window.innerHeight;
    const p = Math.max(0, Math.min(1, docHeight ? scrollTop/docHeight : 0));
    progress && (progress.style.setProperty('--p', p.toFixed(4)));
  }
  updateProgress();
  document.addEventListener('scroll', updateProgress, { passive: true });

  if (themeBtn) {
    themeBtn.addEventListener('click', function(){
      document.documentElement.classList.toggle('theme-dark');
      const isDark = document.documentElement.classList.contains('theme-dark');
      localStorage.setItem('theme', isDark ? 'dark' : 'light');
      themeBtn.setAttribute('aria-pressed', isDark ? 'true' : 'false');
    });
  }

  // Smooth-scroll for TOC (respects reduce-motion)
  const prefersReduced = window.matchMedia && window.matchMedia('(prefers-reduced-motion: reduce)').matches;
  tocLinks.forEach(a => {
    a.addEventListener('click', (e) => {
      const id = a.getAttribute('href')?.replace('#','');
      const target = id ? document.getElementById(id) : null;
      if (target) {
        e.preventDefault();
        if (prefersReduced) {
          target.scrollIntoView();
        } else {
          target.scrollIntoView({ behavior: 'smooth', block: 'start' });
        }
        history.pushState(null, '', '#' + id);
      }
    });
  });

  // Auto-number footnotes (sup.fn-ref -> footnotes list)
  const fns = document.querySelectorAll('sup.fn-ref');
  const fnRoot = document.querySelector('.footnotes ol');
  if (fns.length && fnRoot) {
    fns.forEach((sup, i) => {
      const n = (i+1).toString();
      sup.textContent = n;
      const id = sup.dataset.id || ('fn'+n);
      sup.id = 'ref-' + id;
      const li = document.createElement('li');
      li.id = id;
      li.innerHTML = sup.getAttribute('data-note') || ('Сноска ' + n);
      fnRoot.appendChild(li);
    });
  }
})();