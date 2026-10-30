/* RailToc 的原生实现：层级轨道、弹簧飞机与滚动定位，复用主题的滚动器。 */
(function () {
  'use strict';

  window.initRailToc = function (options) {
    var toc = document.querySelector('[data-rail-toc]');
    if (!toc || toc.dataset.ready) return;
    toc.dataset.ready = 'true';
    options = options || {};

    var viewport = toc.querySelector('.rail_toc_scroll');
    var list = viewport.querySelector('.toc');
    var body = document.getElementById('post-content');
    var motionQuery = window.matchMedia('(prefers-reduced-motion: reduce)');
    var desktopQuery = window.matchMedia('(min-width: 1100px)');
    var items = [];

    Array.prototype.forEach.call(list.querySelectorAll('.toc-link'), function (link) {
      var id;
      try { id = decodeURIComponent(link.hash.slice(1)); } catch (e) { return; }
      var target = document.getElementById(id);
      if (!target) return;
      var depth = 0;
      var parent = link.parentElement.parentElement;
      while (parent && parent !== list) {
        if (parent.tagName === 'OL') depth++;
        parent = parent.parentElement;
      }
      items.push({ link: link, target: target, depth: depth });
    });
    if (!items.length) return;

    // 先读取嵌套层级，再展开行，以便同一条 SVG 轨道穿过所有目录项。
    list.textContent = '';
    items.forEach(function (item) {
      item.row = document.createElement('li');
      item.row.className = 'toc-item';
      item.link.style.setProperty('--toc-depth', item.depth);
      item.row.appendChild(item.link);
      list.appendChild(item.row);
    });

    var ns = 'http://www.w3.org/2000/svg';
    function svgElement(name, attrs, parent) {
      var element = document.createElementNS(ns, name);
      Object.keys(attrs).forEach(function (key) { element.setAttribute(key, attrs[key]); });
      if (parent) parent.appendChild(element);
      return element;
    }

    var svg = svgElement('svg', { 'class': 'rail_toc_track', 'aria-hidden': 'true' });
    var defs = svgElement('defs', {}, svg);
    var fade = svgElement('linearGradient', { id: 'rail-toc-fade', gradientUnits: 'userSpaceOnUse', x1: 0, y1: 0, x2: 0 }, defs);
    svgElement('stop', { offset: 0, 'stop-color': 'black' }, fade);
    svgElement('stop', { offset: 1, 'stop-color': 'white' }, fade);
    var trackMask = svgElement('mask', { id: 'rail-toc-track-mask', maskUnits: 'userSpaceOnUse', x: -8, y: -8 }, defs);
    var trackRect = svgElement('rect', { x: -8, y: -8, fill: 'url(#rail-toc-fade)' }, trackMask);
    var nodeMask = svgElement('mask', { id: 'rail-toc-node-mask', maskUnits: 'userSpaceOnUse', x: -8, y: -8 }, defs);
    var nodeRect = svgElement('rect', { x: -8, y: -8, fill: 'white' }, nodeMask);
    var trackGroup = svgElement('g', { mask: 'url(#rail-toc-track-mask)' }, svg);
    var track = svgElement('path', { fill: 'none', stroke: 'currentColor', 'stroke-width': 1.25, 'stroke-dasharray': '2 5', 'stroke-linecap': 'round', 'stroke-linejoin': 'round' }, trackGroup);
    var progress = svgElement('path', { 'class': 'rail_toc_progress', fill: 'none', 'stroke-width': 1.25, 'stroke-linejoin': 'round' }, trackGroup);
    var nodeGroup = svgElement('g', { mask: 'url(#rail-toc-node-mask)' }, svg);
    items.forEach(function (item) {
      item.cutout = svgElement('circle', { r: 4, fill: 'black' }, trackMask);
      item.dot = svgElement('circle', { 'class': 'rail_toc_node', r: 3, 'stroke-width': 1.25 }, nodeGroup);
    });
    var holes = [trackMask, nodeMask].map(function (mask) {
      return svgElement('circle', { r: 4, fill: 'black' }, mask);
    });
    var plane = svgElement('svg', { 'class': 'rail_toc_plane', viewBox: '0 0 24 24', 'aria-hidden': 'true' });
    svgElement('path', { d: 'M12 2 20.5 21 12 17.5 3.5 21z', fill: 'currentColor', stroke: 'currentColor', 'stroke-width': 1.5, 'stroke-linejoin': 'round' }, plane);
    list.appendChild(svg);
    list.appendChild(plane);

    var total = 0;
    var distance = 0;
    var destination = 0;
    var velocity = 0;
    var angle = 180;
    var angleTarget = 180;
    var angleVelocity = 0;
    var facing = 1;
    var turnFrom = 0;
    var active = -1;
    var pinned = null;
    var userScrolled = false;
    var placed = false;
    var frame = 0;
    var syncFrame = 0;
    var measureFrame = 0;
    var previousTime = 0;

    function offset() {
      var nav = document.querySelector('.nav');
      return nav ? nav.getBoundingClientRect().bottom + 24 : 96;
    }

    function keepVisible(index) {
      var row = items[index].row;
      var top = row.offsetTop;
      var bottom = top + row.offsetHeight;
      if (top < viewport.scrollTop + 12 || bottom > viewport.scrollTop + viewport.clientHeight - 12) {
        viewport.scrollTop = Math.max(0, top - (viewport.clientHeight - row.offsetHeight) / 2);
      }
    }

    function pose(value, snap) {
      value = Math.max(0, Math.min(total, value));
      var point = track.getPointAtLength(value);
      var before = track.getPointAtLength(Math.max(0, value - 1));
      var after = track.getPointAtLength(Math.min(total, value + 1));
      var heading = Math.atan2(after.y - before.y, after.x - before.x) * 180 / Math.PI + 90 + (facing < 0 ? 180 : 0);
      angleTarget = heading + 360 * Math.round((angle - heading) / 360);
      if (snap) angle = angleTarget;
      plane.style.transform = 'translate(' + point.x + 'px,' + point.y + 'px) rotate(' + angle + 'deg)';
      holes.forEach(function (hole) {
        hole.setAttribute('cx', point.x);
        hole.setAttribute('cy', point.y);
      });
      progress.setAttribute('stroke-dashoffset', total - value);
      var index = 0;
      items.forEach(function (item, i) {
        var reached = item.length <= value + .5;
        item.dot.classList.toggle('is-reached', reached);
        if (reached) index = i;
      });
      if (active !== index) {
        if (active >= 0) items[active].link.removeAttribute('aria-current');
        active = index;
        items[active].link.setAttribute('aria-current', 'location');
        keepVisible(active);
      }
    }

    function animate(time) {
      frame = 0;
      var elapsed = time - previousTime;
      // 后台标签页可能暂停动画；恢复时直接归位，不让飞机慢慢补跑。
      if (elapsed > 100) {
        distance = destination;
        velocity = angleVelocity = 0;
        pose(distance, true);
        return;
      }
      var dt = Math.min(elapsed / 1000 || 1 / 60, .032);
      previousTime = time;
      // 小步积分让 60Hz / 120Hz 显示器使用相同的弹簧参数。
      for (var step = 0; step < 4; step++) {
        velocity += ((destination - distance) * 140 - velocity * 26) / .6 * dt / 4;
        distance += velocity * dt / 4;
        angleVelocity += ((angleTarget - angle) * 260 - angleVelocity * 30) * dt / 4;
        angle += angleVelocity * dt / 4;
      }
      pose(distance, false);
      if (Math.abs(destination - distance) > .05 || Math.abs(velocity) > .05 || Math.abs(angleTarget - angle) > .1 || Math.abs(angleVelocity) > .1) {
        frame = requestAnimationFrame(animate);
      } else {
        distance = destination;
        velocity = angleVelocity = 0;
        pose(distance, true);
      }
    }

    function aim(next) {
      if ((next - turnFrom) * facing > 0) turnFrom = next;
      else if (Math.abs(next - turnFrom) > 2) {
        facing *= -1;
        turnFrom = next;
      }
      destination = next;
      if (!placed || motionQuery.matches) {
        distance = next;
        velocity = angleVelocity = 0;
        pose(next, true);
        placed = true;
      } else if (!frame) {
        previousTime = performance.now();
        frame = requestAnimationFrame(animate);
      }
    }

    function sync() {
      if (!total || !toc.open) return;
      if (pinned !== null) return aim(items[pinned].length);
      var scrollTop = window.scrollY;
      var viewHeight = window.innerHeight;
      var remaining = Math.max(0, document.documentElement.scrollHeight - viewHeight - scrollTop);
      var line = Math.min(offset(), scrollTop);
      var anchor = line + Math.max(0, viewHeight - line - remaining);
      var tops = items.map(function (item) { return item.target.getBoundingClientRect().top; });
      var index = -1;
      tops.forEach(function (top, i) { if (top <= anchor) index = i; });
      if (index < 0) return aim(items[0].length);
      if (index === items.length - 1) return aim(items[index].length);
      var span = tops[index + 1] - tops[index];
      var fraction = span > 0 ? Math.min(1, Math.max(0, (anchor - tops[index]) / span)) : 0;
      aim(items[index].length + fraction * (items[index + 1].length - items[index].length));
    }

    function measure() {
      if (!toc.open || !list.offsetHeight) return;
      var nodes = items.map(function (item) {
        return { x: 5 + item.depth * 14, y: item.row.offsetTop + item.row.offsetHeight / 2 };
      });
      var points = [{ x: nodes[0].x, y: 0 }, nodes[0]];
      nodes.forEach(function (to, i) {
        if (!i) return;
        var from = nodes[i - 1];
        if (from.x !== to.x) {
          var bend = (to.y - from.y) * .3;
          points.push({ x: from.x, y: from.y + bend }, { x: to.x, y: to.y - bend });
        }
        points.push(to);
      });
      var d = points.map(function (point, i) { return (i ? 'L' : 'M') + point.x + ' ' + point.y; }).join(' ');
      var width = Math.max.apply(null, nodes.map(function (node) { return node.x; })) + 9;
      var height = list.offsetHeight;
      svg.setAttribute('width', width);
      svg.setAttribute('height', height);
      fade.setAttribute('y2', Math.max(1, nodes[0].y - 4));
      [trackMask, nodeMask, trackRect, nodeRect].forEach(function (element) {
        element.setAttribute('width', width + 16);
        element.setAttribute('height', height + 16);
      });
      track.setAttribute('d', d);
      progress.setAttribute('d', d);
      total = track.getTotalLength();
      progress.setAttribute('stroke-dasharray', total + ' ' + total);
      items.forEach(function (item, i) {
        [item.dot, item.cutout].forEach(function (circle) {
          circle.setAttribute('cx', nodes[i].x);
          circle.setAttribute('cy', nodes[i].y);
        });
        var low = 0;
        var high = total;
        for (var j = 0; j < 24; j++) {
          var mid = (low + high) / 2;
          if (track.getPointAtLength(mid).y < nodes[i].y) low = mid;
          else high = mid;
        }
        item.length = high;
      });
      placed = false;
      sync();
    }

    function scheduleMeasure() {
      if (measureFrame) return;
      measureFrame = requestAnimationFrame(function () { measureFrame = 0; measure(); });
    }

    function release() { userScrolled = true; }
    window.addEventListener('scroll', function () {
      if (pinned !== null && userScrolled) pinned = null;
      if (!syncFrame) syncFrame = requestAnimationFrame(function () { syncFrame = 0; sync(); });
    }, { passive: true });
    window.addEventListener('wheel', release, { passive: true });
    window.addEventListener('touchstart', release, { passive: true });
    window.addEventListener('pointerdown', release, { passive: true });
    window.addEventListener('keydown', function (event) {
      if (['ArrowUp', 'ArrowDown', 'PageUp', 'PageDown', 'Home', 'End', ' '].indexOf(event.key) !== -1) release();
    });
    window.addEventListener('resize', scheduleMeasure);
    window.addEventListener('load', scheduleMeasure);
    window.addEventListener('popstate', function () { pinned = null; sync(); });
    motionQuery.addEventListener('change', sync);
    desktopQuery.addEventListener('change', function () { toc.open = desktopQuery.matches; });
    toc.addEventListener('toggle', scheduleMeasure);

    items.forEach(function (item, index) {
      item.link.addEventListener('click', function (event) {
        if (event.button !== 0 || event.metaKey || event.ctrlKey || event.shiftKey || event.altKey) return;
        event.preventDefault();
        pinned = index;
        userScrolled = false;
        sync();
        document.dispatchEvent(new CustomEvent('blog:section-select', { detail: { id: item.target.id } }));
        if (window.location.hash !== item.link.hash) history.pushState(null, '', item.link.hash);
        if (options.scrollTo) options.scrollTo(item.target, offset());
        else window.scrollTo({ top: item.target.getBoundingClientRect().top + window.scrollY - offset(), behavior: motionQuery.matches ? 'auto' : 'smooth' });
      });
    });

    if (window.ResizeObserver) {
      var observer = new ResizeObserver(scheduleMeasure);
      observer.observe(list);
      observer.observe(body);
    }
    if (document.fonts) document.fonts.ready.then(scheduleMeasure);
    toc.open = desktopQuery.matches;
    measure();
  };
})();
