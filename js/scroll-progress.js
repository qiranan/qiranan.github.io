/* ScrollProgress 的原生实现，与右侧目录共用章节和跳转逻辑。 */
(function () {
  'use strict';

  window.initScrollProgress = function () {
    var root = document.querySelector('[data-scroll-progress]');
    if (!root || root.dataset.ready) return;

    var surface = root.querySelector('.scroll_progress_surface');
    var toggle = root.querySelector('.scroll_progress_toggle');
    var label = root.querySelector('.scroll_progress_label');
    var panel = root.querySelector('.scroll_progress_panel');
    var list = root.querySelector('.scroll_progress_items');
    var highlight = root.querySelector('.scroll_progress_highlight');
    var ring = root.querySelector('.scroll_progress_ring');
    var fill = root.querySelector('.scroll_progress_ring_fill');
    var motionQuery = window.matchMedia('(prefers-reduced-motion: reduce)');
    var sections = [];

    Array.prototype.forEach.call(document.querySelectorAll('[data-rail-toc] .toc-link'), function (source) {
      var id;
      try { id = decodeURIComponent(source.hash.slice(1)); } catch (e) { return; }
      var target = document.getElementById(id);
      if (!target) return;
      var row = document.createElement('li');
      var link = document.createElement('a');
      var dot = document.createElement('span');
      var text = document.createElement('span');
      dot.className = 'scroll_progress_dot';
      dot.setAttribute('aria-hidden', 'true');
      text.textContent = source.textContent.trim();
      link.className = 'scroll_progress_link';
      link.href = source.getAttribute('href');
      link.appendChild(dot);
      link.appendChild(text);
      row.appendChild(link);
      list.appendChild(row);
      sections.push({ id: id, label: text.textContent, target: target, source: source, link: link, row: row });
    });
    if (!sections.length) return;
    root.dataset.ready = 'true';

    var open = false;
    var active = -1;
    var pinned = null;
    var userScrolled = false;
    var updateFrame = 0;
    var progressFrame = 0;
    var currentProgress = 0;
    var targetProgress = 0;
    var progressVelocity = 0;
    var previousTime = 0;
    var lastPercent = -1;

    function measure() {
      var layer = open ? panel : toggle;
      surface.style.width = (layer.offsetWidth + 2) + 'px';
      surface.style.height = (layer.offsetHeight + 2) + 'px';
      surface.style.borderRadius = (open ? 26 : toggle.offsetHeight / 2) + 'px';
      if (active >= 0) {
        highlight.style.height = sections[active].row.offsetHeight + 'px';
        highlight.style.transform = 'translateY(' + sections[active].row.offsetTop + 'px)';
      }
    }

    function keepVisible() {
      if (!open || active < 0) return;
      var row = sections[active].row;
      if (row.offsetTop < panel.scrollTop || row.offsetTop + row.offsetHeight > panel.scrollTop + panel.clientHeight - 12) {
        panel.scrollTop = Math.max(0, row.offsetTop - (panel.clientHeight - row.offsetHeight) / 2);
      }
    }

    function activate(index) {
      if (index === active) return;
      if (active >= 0) sections[active].link.removeAttribute('aria-current');
      active = index;
      var section = sections[index];
      section.link.setAttribute('aria-current', 'location');
      var text = document.createElement('span');
      text.dataset.slot = 'scroll-progress-label';
      text.textContent = section.label;
      label.replaceChildren(text);
      toggle.title = section.label;
      toggle.setAttribute('aria-label', '展开章节目录，当前章节：' + section.label);
      measure();
      keepVisible();
    }

    function setOpen(next, restoreFocus) {
      if (open === next) return;
      open = next;
      // 用 inert 将淡出的那一层移出键盘与读屏访问顺序。
      panel.inert = !open;
      panel.setAttribute('aria-hidden', String(!open));
      toggle.setAttribute('aria-hidden', String(open));
      toggle.setAttribute('aria-expanded', String(open));
      root.classList.toggle('is-open', open);
      measure();
      if (open) {
        keepVisible();
        sections[Math.max(0, active)].link.focus({ preventScroll: true });
        toggle.inert = true;
      } else {
        toggle.inert = false;
        if (restoreFocus) toggle.focus({ preventScroll: true });
      }
    }

    function drawProgress() {
      fill.setAttribute('stroke-dashoffset', 100 - Math.max(0, Math.min(1, currentProgress)) * 100);
    }

    function animateProgress(time) {
      progressFrame = 0;
      var elapsed = time - previousTime;
      previousTime = time;
      if (elapsed > 100 || motionQuery.matches) {
        currentProgress = targetProgress;
        progressVelocity = 0;
        drawProgress();
        return;
      }
      var dt = Math.min(elapsed / 1000 || 1 / 60, .032) / 4;
      for (var i = 0; i < 4; i++) {
        progressVelocity += ((targetProgress - currentProgress) * 120 - progressVelocity * 30) / .3 * dt;
        currentProgress += progressVelocity * dt;
      }
      if (Math.abs(targetProgress - currentProgress) < .0001 && Math.abs(progressVelocity) < .0001) {
        currentProgress = targetProgress;
        progressVelocity = 0;
      } else progressFrame = requestAnimationFrame(animateProgress);
      drawProgress();
    }

    function update() {
      updateFrame = 0;
      var remaining = Math.max(0, document.documentElement.scrollHeight - innerHeight - scrollY);
      var scrollable = document.documentElement.scrollHeight - innerHeight;
      targetProgress = scrollable > 0 ? Math.min(1, Math.max(0, scrollY / scrollable)) : 1;
      var percent = Math.round(targetProgress * 100);
      if (percent !== lastPercent) {
        ring.setAttribute('aria-valuenow', percent);
        lastPercent = percent;
      }
      if (!root.classList.contains('is-ready') || motionQuery.matches) {
        currentProgress = targetProgress;
        progressVelocity = 0;
        drawProgress();
      } else if (!progressFrame && targetProgress !== currentProgress) {
        previousTime = performance.now();
        progressFrame = requestAnimationFrame(animateProgress);
      }

      if (pinned !== null) return activate(pinned);
      var nav = document.querySelector('.nav');
      var offset = nav ? nav.getBoundingClientRect().bottom + 24 : 120;
      var line = Math.min(offset, scrollY);
      var anchor = line + Math.max(0, innerHeight - line - remaining);
      var index = 0;
      sections.forEach(function (section, i) {
        if (section.target.getBoundingClientRect().top <= anchor + 1) index = i;
      });
      activate(index);
    }

    function scheduleUpdate() {
      if (!updateFrame) updateFrame = requestAnimationFrame(update);
    }

    toggle.addEventListener('click', function () { setOpen(true); });
    document.addEventListener('pointerdown', function (event) {
      userScrolled = true;
      if (open && !root.contains(event.target)) setOpen(false, false);
    });
    document.addEventListener('keydown', function (event) {
      if (event.key === 'Escape' && open) {
        event.preventDefault();
        setOpen(false, true);
      }
      if (['ArrowUp', 'ArrowDown', 'PageUp', 'PageDown', 'Home', 'End', ' '].indexOf(event.key) !== -1) userScrolled = true;
    });
    document.addEventListener('focusin', function (event) {
      if (open && !root.contains(event.target)) setOpen(false, false);
    });
    sections.forEach(function (section) {
      section.link.addEventListener('click', function (event) {
        if (event.button !== 0 || event.metaKey || event.ctrlKey || event.shiftKey || event.altKey) return;
        event.preventDefault();
        setOpen(false, true);
        // 原目录负责平滑滚动、中文锚点、落点避让与飞机定位。
        section.source.click();
      });
    });
    document.addEventListener('blog:section-select', function (event) {
      var index = sections.findIndex(function (section) { return section.id === event.detail.id; });
      if (index < 0) return;
      pinned = index;
      userScrolled = false;
      activate(index);
    });
    window.addEventListener('scroll', function () {
      if (userScrolled) pinned = null;
      scheduleUpdate();
    }, { passive: true });
    window.addEventListener('wheel', function () { userScrolled = true; }, { passive: true });
    window.addEventListener('touchstart', function () { userScrolled = true; }, { passive: true });
    window.addEventListener('popstate', function () { pinned = null; scheduleUpdate(); });
    window.addEventListener('resize', function () { measure(); scheduleUpdate(); });
    window.addEventListener('load', scheduleUpdate);
    motionQuery.addEventListener('change', scheduleUpdate);

    root.hidden = false;
    document.body.classList.add('has-scroll-progress');
    update();
    measure();
    requestAnimationFrame(function () { root.classList.add('is-ready'); });
    if (window.ResizeObserver) {
      var observer = new ResizeObserver(function () { measure(); scheduleUpdate(); });
      observer.observe(toggle);
      observer.observe(panel);
      observer.observe(document.getElementById('post-content'));
    }
    if (document.fonts) document.fonts.ready.then(function () { measure(); scheduleUpdate(); });
  };
})();
