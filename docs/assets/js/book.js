/* Book Psychoanalytic Theme — interactions */
(function(){
  const root = document.documentElement;
  const progress = document.querySelector('.progress');
  const tocLinks = document.querySelectorAll('.toc a');
  function updateProgress(){
    const scrollTop = window.scrollY || document.documentElement.scrollTop;
    const docHeight = document.documentElement.scrollHeight - window.innerHeight;
    const p = Math.max(0, Math.min(1, docHeight ? scrollTop/docHeight : 0));
    progress && (progress.style.setProperty('--p', p.toFixed(4)));
  }
  updateProgress();
  document.addEventListener('scroll', updateProgress, { passive: true });

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

  const contactForm = document.getElementById('contact-form');
  if (contactForm) {
    const feedback = contactForm.querySelector('.form-feedback');
    let fallbackSubmitted = false;
    const handleSubmit = function(event) {
      event.preventDefault();
      feedback && feedback.classList.remove('is-error', 'is-success');
      if (feedback) {
        feedback.textContent = 'Отправляем сообщение...';
      }
      const formData = new FormData(contactForm);
      fetch(contactForm.action, {
        method: 'POST',
        headers: { 'Accept': 'application/json' },
        body: formData
      }).then(function(response){
        if (!response.ok) { throw new Error('Network'); }
        if (feedback) {
          feedback.textContent = 'Спасибо! Сообщение отправлено.';
          feedback.classList.add('is-success');
        }
        contactForm.reset();
      }).catch(function(){
        if (!fallbackSubmitted) {
          fallbackSubmitted = true;
          contactForm.removeEventListener('submit', handleSubmit);
          contactForm.submit();
          return;
        }
        if (feedback) {
          feedback.textContent = 'Не удалось отправить. Напишите, пожалуйста, в Telegram или WhatsApp.';
          feedback.classList.add('is-error');
        }
      });
    };
    contactForm.addEventListener('submit', handleSubmit);
  }
})();