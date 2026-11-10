(function () {
  'use strict';

  if (window.__okorolevaAnalyticsBootstrapped) return;
  window.__okorolevaAnalyticsBootstrapped = true;

  var productionHost = window.location.hostname === 'okoroleva.com' || window.location.hostname === 'www.okoroleva.com';
  var excluded = !productionHost;
  try {
    excluded = excluded || window.localStorage.getItem('okoroleva.analytics.excluded.v1') === '1';
  } catch (error) {
    // A browser that has not saved an exclusion keeps ordinary measurement.
  }

  window['ga-disable-G-S88TQXVMSD'] = excluded;
  if (excluded) return;

  window.dataLayer = window.dataLayer || [];
  window.gtag = window.gtag || function () { window.dataLayer.push(arguments); };
  window.gtag('js', new Date());
  window.gtag('config', 'G-S88TQXVMSD');

  var googleTag = document.createElement('script');
  googleTag.id = 'gaTag';
  googleTag.async = true;
  googleTag.src = 'https://www.googletagmanager.com/gtag/js?id=G-S88TQXVMSD';
  document.head.appendChild(googleTag);

  window.ym = window.ym || function () { (window.ym.a = window.ym.a || []).push(arguments); };
  window.ym.l = 1 * new Date();
  function loadMetrika() {
    if (document.getElementById('ymTag')) return;
    var tag = document.createElement('script');
    tag.id = 'ymTag';
    tag.async = true;
    tag.src = 'https://mc.yandex.ru/metrika/tag.js';
    document.head.appendChild(tag);
  }
  if ('requestIdleCallback' in window) {
    window.requestIdleCallback(loadMetrika, { timeout: 4000 });
  } else if (document.readyState === 'complete') {
    loadMetrika();
  } else {
    window.addEventListener('load', loadMetrika, { once: true });
  }
  window.ym(105124237, 'init', {
    accurateTrackBounce: true,
    trackLinks: true,
    clickmap: true,
    webvisor: true
  });
}());
