(function(){
  const progress=document.querySelector('.progress');
  const update=()=>{const h=document.documentElement.scrollHeight-innerHeight;progress?.style.setProperty('--p',h?Math.min(1,scrollY/h):0)};
  update();addEventListener('scroll',update,{passive:true});
  const menu=document.querySelector('.menu-toggle'),nav=document.querySelector('#menu');
  menu?.addEventListener('click',()=>{const open=menu.getAttribute('aria-expanded')==='true';menu.setAttribute('aria-expanded',String(!open));nav?.classList.toggle('is-open',!open)});
  nav?.querySelectorAll('a').forEach(a=>a.addEventListener('click',()=>{nav.classList.remove('is-open');menu?.setAttribute('aria-expanded','false')}));
  const items=document.querySelectorAll('.reveal');
  if(!('IntersectionObserver'in window)||matchMedia('(prefers-reduced-motion: reduce)').matches){items.forEach(x=>x.classList.add('is-visible'));return}
  const observer=new IntersectionObserver(entries=>entries.forEach(e=>{if(e.isIntersecting){e.target.classList.add('is-visible');observer.unobserve(e.target)}}),{threshold:.12});
  items.forEach(x=>observer.observe(x));
})();

