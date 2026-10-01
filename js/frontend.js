/* ==========================================================================
   安的角落 —— 前端动画
   --------------------------------------------------------------------------
   开场动画：环形声波（按加载进度顺时针画出来）→ 头像落进中间的圆环
             → 点击进入 → 头像平移到左上角 → 毛玻璃状态栏从头像处向右弹出
   转场动画：两张“纸”从中间合上/打开，接缝处一排声波条，右下角折角展开
             （Jekyll 是多页站点，所以离开/进场各演一半，跨页也连贯）
   磁力光标：四个直角括号被可吸附元素“吸”过去，并描一遍该元素的描边图标
   所有动画参数（缓动曲线）都取自参考站点。
   ========================================================================== */
(function () {
  'use strict';

  var gsap = window.gsap;
  var root = document.documentElement;
  var params = new URLSearchParams(window.location.search);
  var reduce = window.matchMedia('(prefers-reduced-motion: reduce)').matches;
  var debugNoSplash = params.has('nosplash');
  var debugNoIntro = params.has('nointro');

  /* GSAP 没加载成功就把内容原样放出来，页面必须还能读 */
  if (!gsap) {
    root.classList.remove('has-splash', 'enter-transition');
    return;
  }

  gsap.registerPlugin(window.ScrollTrigger);
  if (window.CustomEase) gsap.registerPlugin(window.CustomEase);
  if (window.SplitText) gsap.registerPlugin(window.SplitText);

  /* 参考站点的三条曲线，这里用 CustomEase 原样搬过来 */
  if (window.CustomEase) {
    window.CustomEase.create('ease_in', 'M0,0 C0.6,0,0.8,0.4,1,1');
    window.CustomEase.create('ease_out', 'M0,0 C0.2,0.9,0.45,1,1,1');
    window.CustomEase.create('ease_inout', 'M0,0 C0.7,0,0.3,1,1,1');
  }
  var EASE_IN = window.CustomEase ? 'ease_in' : 'power2.in';
  var EASE_OUT = window.CustomEase ? 'ease_out' : 'power2.out';
  var EASE_INOUT = window.CustomEase ? 'ease_inout' : 'power2.inOut';

  if (debugNoSplash && root.classList.contains('has-splash')) {
    root.classList.remove('has-splash');
    root.classList.add('enter-transition');
  }

  var introPlayed = false;
  /* 开场还没结束前，站内链接一律不跳转（头像本身就是个 <a>） */
  var splashActive = false;

  /* ======================================================================
     平滑滚动（Lenis）+ ScrollTrigger 同步
     ====================================================================== */
  var lenis = null;

  function initScroll() {
    if (reduce || !window.Lenis) return;
    lenis = new window.Lenis({
      duration: 1,
      easing: function (t) { return Math.min(1, 1.001 - Math.pow(2, -10 * t)); },
      smoothWheel: true,
      autoRaf: false
    });
    lenis.on('scroll', window.ScrollTrigger.update);
    gsap.ticker.add(function (time) { lenis.raf(time * 1000); });
    gsap.ticker.lagSmoothing(0);
  }

  function lockScroll(on) {
    if (lenis) {
      if (on) { lenis.stop(); } else { lenis.start(); }
    } else {
      document.body.style.overflow = on ? 'hidden' : '';
    }
  }

  /* ======================================================================
     磁力光标 + 吸附目标的 SVG 描边动画
     ====================================================================== */
  function drawIcon(el) {
    if (!el.hasAttribute || !el.hasAttribute('data-stroke')) return;
    var shapes = el.querySelectorAll('svg.icon path, svg.icon circle, svg.icon rect, svg.icon line, svg.icon polyline');
    Array.prototype.forEach.call(shapes, function (s, i) {
      var len;
      try { len = s.getTotalLength(); } catch (e) { return; }
      if (!len) return;
      gsap.killTweensOf(s);
      /* 先整条藏起来（dash 长度 = 路径长度），再描出来 */
      gsap.set(s, { strokeDasharray: len, strokeDashoffset: len });
      gsap.to(s, {
        strokeDashoffset: 0,
        duration: .8,
        ease: EASE_OUT,
        delay: i * .06,
        overwrite: true,
        onComplete: function () {
          /* 描完之后恢复成普通状态，方便下次再描一遍 */
          gsap.set(s, { clearProps: 'strokeDasharray,strokeDashoffset' });
        }
      });
    });
  }

  /* canvas 里的卡片不是 DOM 元素，光标吸附得靠这个接口把矩形喂进来 */
  var cursorApi = null;
  /* 友链照片墙的实例，换主题时要让它重取颜色 */
  var friendWall = null;

  function initCursor() {
    var el = document.getElementById('cursor');
    var label = document.getElementById('cursor-label');
    if (!el || reduce) return;
    if (!window.matchMedia('(hover: hover) and (pointer: fine)').matches) return;

    root.classList.add('has-cursor');

    var BASE = 2.6;             /* rem */
    var current = null;         /* DOM 元素，或 { getRect, label } 这样的虚拟目标 */

    function rectOf(t) {
      return t.getBoundingClientRect ? t.getBoundingClientRect() : t.getRect();
    }

    function labelOf(t) {
      return t.getAttribute ? t.getAttribute('data-cursor') : t.label;
    }

    function enter(target) {
      var r = rectOf(target);
      var pad = Math.min(window.innerWidth / 60, 26);
      el.style.setProperty('--w', (r.width + pad) + 'px');
      el.style.setProperty('--h', (r.height + pad) + 'px');

      var text = labelOf(target);
      if (label && text) {
        label.textContent = text;
        gsap.to(label, { opacity: 1, duration: .25, ease: EASE_OUT, overwrite: true });
      } else if (label) {
        gsap.to(label, { opacity: 0, duration: .15, overwrite: true });
      }
      /* canvas 卡片里没有 SVG，只有 DOM 目标才描边 */
      if (target.getBoundingClientRect) drawIcon(target);
    }

    function leave() {
      el.style.setProperty('--w', BASE + 'rem');
      el.style.setProperty('--h', BASE + 'rem');
      if (label) gsap.to(label, { opacity: 0, duration: .15, overwrite: true });
    }

    window.addEventListener('mousemove', function (e) {
      var x = e.clientX;
      var y = e.clientY;
      if (current) {
        /* 核心就是这个 0.1：光标被拉向目标中心，越近越“黏” */
        var r = rectOf(current);
        var cx = r.left + r.width / 2;
        var cy = r.top + r.height / 2;
        x = cx + (x - cx) * 0.1;
        y = cy + (y - cy) * 0.1;
      }
      el.style.transform = 'translate(' + x + 'px,' + y + 'px)';
    }, { passive: true });

    /* 事件委托：友链墙之外的普通元素靠这里吸附 */
    document.addEventListener('mouseover', function (e) {
      /* 照片墙自己管吸附，别在这儿被清掉 */
      if (e.target && e.target.closest && e.target.closest('#friendwall-wrap')) return;
      var t = e.target && e.target.closest ? e.target.closest('[data-magnetic]') : null;
      if (t === current) return;
      if (current) leave();
      current = t;
      if (t) enter(t);
    });

    document.addEventListener('mouseleave', function () {
      if (current) { leave(); current = null; }
    });

    /* 给 canvas 照片墙用 */
    cursorApi = {
      set: function (getRect, text) {
        if (current) leave();
        current = { getRect: getRect, label: text };
        enter(current);
      },
      clear: function () {
        if (!current) return;
        leave();
        current = null;
      }
    };
  }

  /* ======================================================================
     进场显现：逐行遮罩 / 分组淡入 / 正文逐块升起
     ====================================================================== */
  function prepareHiddenStates() {
    if (reduce) return;
    var reveals = document.querySelectorAll('.reveal > *');
    if (reveals.length) gsap.set(reveals, { yPercent: 115 });

    var staggers = document.querySelectorAll('[data-stagger] > *');
    if (staggers.length) gsap.set(staggers, { opacity: 0, y: 18 });

    var bodies = document.querySelectorAll('[data-reveal-body] > *');
    if (bodies.length) gsap.set(bodies, { opacity: 0, y: 24 });
  }

  function revealAll() {
    gsap.set('.reveal > *', { clearProps: 'transform' });
    gsap.set('[data-stagger] > *', { clearProps: 'opacity,transform' });
    gsap.set('[data-reveal-body] > *', { clearProps: 'opacity,transform' });
    gsap.set('.nav_item_label > span', { clearProps: 'transform' });
  }

  function initSplitLines() {
    if (reduce || !window.SplitText) return;
    gsap.utils.toArray('[data-split-lines]').forEach(function (el) {
      var played = false;
      window.SplitText.create(el, {
        type: 'lines',
        mask: 'lines',
        autoSplit: true,
        onSplit: function (self) {
          if (played) {
            gsap.set(self.lines, { yPercent: 0 });
            return;
          }
          return gsap.from(self.lines, {
            yPercent: 115,
            duration: 1,
            ease: EASE_INOUT,
            stagger: .08,
            onComplete: function () { played = true; },
            scrollTrigger: { trigger: el, start: 'top 92%', once: true }
          });
        }
      });
    });
  }

  function initReveals() {
    var ST = window.ScrollTrigger;

    /* 标题、日期这类整行升起 */
    var revealParents = gsap.utils.toArray('.reveal');
    if (revealParents.length) {
      ST.batch(revealParents, {
        start: 'top 92%',
        once: true,
        onEnter: function (batch) {
          var kids = [];
          batch.forEach(function (p) { if (p.firstElementChild) kids.push(p.firstElementChild); });
          gsap.to(kids, { yPercent: 0, duration: 1, ease: EASE_INOUT, stagger: .09 });
        }
      });
    }

    /* 标签、社交按钮、档案这类成组元素 */
    var staggerGroups = gsap.utils.toArray('[data-stagger]');
    if (staggerGroups.length) {
      ST.batch(staggerGroups, {
        start: 'top 92%',
        once: true,
        onEnter: function (batch) {
          var kids = [];
          batch.forEach(function (g) {
            Array.prototype.push.apply(kids, Array.prototype.slice.call(g.children));
          });
          gsap.to(kids, { opacity: 1, y: 0, duration: .9, ease: EASE_OUT, stagger: .05 });
        }
      });
    }

    /* 文章正文逐块升起 */
    var bodyBlocks = gsap.utils.toArray('[data-reveal-body] > *');
    if (bodyBlocks.length) {
      ST.batch(bodyBlocks, {
        start: 'top 94%',
        once: true,
        onEnter: function (batch) {
          gsap.to(batch, { opacity: 1, y: 0, duration: .8, ease: EASE_OUT, stagger: .05 });
        }
      });
    }

    /* 区块标题上的图标，进入视口时描一遍 */
    gsap.utils.toArray('.section_head_icon').forEach(function (el) {
      ST.create({
        trigger: el,
        start: 'top 95%',
        once: true,
        onEnter: function () { drawIcon(el.parentNode); }
      });
    });
  }

  function introPlay() {
    if (introPlayed) return;
    introPlayed = true;

    if (reduce || debugNoIntro) {
      revealAll();
      initTimeline();
      return;
    }

    initSplitLines();
    initReveals();
    initTimeline();
    window.ScrollTrigger.refresh();
  }

  /* ======================================================================
     比赛：横向滑动时间轴（sticky + 进度映射，参考 007 的做法）
     ====================================================================== */
  function initTimeline() {
    var wrap = document.getElementById('tl-wrap');
    var track = document.getElementById('tl-track');
    if (!wrap || !track) return;

    var bar = document.getElementById('tl-progress-bar');
    var distance = 0;
    var pinned = false;

    function measure() {
      /* offsetWidth 不受 transform 影响，可以安全地反复量 */
      distance = Math.max(0, track.offsetWidth - wrap.clientWidth);
      pinned = distance > 0;
      /* 卷动距离 = 横向距离，这样滚到底正好滑到最后一张 */
      wrap.style.height = pinned ? (distance + window.innerHeight) + 'px' : '';
      if (!pinned) track.style.transform = '';
    }

    measure();
    window.addEventListener('resize', measure);

    if (!pinned) return;

    window.ScrollTrigger.create({
      trigger: wrap,
      start: 'top top',
      end: 'bottom bottom',
      onUpdate: function (self) {
        track.style.transform = 'translateX(' + (-self.progress * distance) + 'px)';
        if (bar) bar.style.width = (self.progress * 100).toFixed(2) + '%';
      },
      onRefresh: function (self) {
        track.style.transform = 'translateX(' + (-self.progress * distance) + 'px)';
      }
    });
  }

  /* ======================================================================
     友链：canvas 无限滑动照片墙
     做法参考 008-02-infinite-scrolling-canvas：
       卡片按网格排布、各自记着 x / y，拖动时整体位移，
       越界就整整一个周期地绕回来 —— 所以往哪个方向拖都到不了头，
       横向纵向都能无限滑。
     在它的基础上补了几件事：
       · 卡片画成「封面 + 头像 + 名字 + 简介」，不再是纯图片
       · 没人操作时缓慢自己漂
       · 鼠标指到哪张，磁力光标就吸附过去，并给那张卡描一遍边框
       · 点一下打开对方的站点
     ====================================================================== */
  function initFriendWall() {
    var canvas = document.getElementById('friendwall');
    var dataEl = document.getElementById('friendwall-data');
    var wrapEl = document.getElementById('friendwall-wrap');
    if (!canvas || !dataEl || !wrapEl || !canvas.getContext) return null;

    var friends;
    try { friends = JSON.parse(dataEl.textContent || '[]'); } catch (e) { return null; }
    if (!friends.length) return null;

    var ctx = canvas.getContext('2d');
    if (!ctx) return null;

    var hint = document.getElementById('friendwall-hint');

    /* 卡片尺寸，单位都是 CSS px */
    var CARD_W = 288;
    var CARD_H = 200;
    var COVER_H = 108;
    var GAP = 32;
    var RADIUS = 10;
    var AVATAR = 40;
    var DRIFT = 16;              /* 自动漂移速度：px/秒 */

    var STEP_X = CARD_W + GAP;
    var STEP_Y = CARD_H + GAP;
    var FONT = '"PingFang SC", "Microsoft YaHei", system-ui, -apple-system, sans-serif';

    var cols = 1, rows = 1;
    var periodX = 1, periodY = 1;
    var offX = 0, offY = 0;
    var cards = [];
    var images = [];
    var hovered = null;
    var dragging = false;
    var dragMoved = 0;
    var lastPt = { x: 0, y: 0 };
    var strokeT = { v: 0 };
    var theme = {};
    var visible = true;
    var needsDraw = true;
    var lastT = 0;

    /* ---------------- 画图小工具 ---------------- */
    function roundRectPath(x, y, w, h, r) {
      ctx.beginPath();
      if (ctx.roundRect) { ctx.roundRect(x, y, w, h, r); return; }
      ctx.moveTo(x + r, y);
      ctx.arcTo(x + w, y, x + w, y + h, r);
      ctx.arcTo(x + w, y + h, x, y + h, r);
      ctx.arcTo(x, y + h, x, y, r);
      ctx.arcTo(x, y, x + w, y, r);
      ctx.closePath();
    }

    /* 只要上面两个角是圆的（封面用） */
    function topRoundPath(x, y, w, h, r) {
      ctx.beginPath();
      ctx.moveTo(x, y + h);
      ctx.lineTo(x, y + r);
      ctx.arcTo(x, y, x + r, y, r);
      ctx.lineTo(x + w - r, y);
      ctx.arcTo(x + w, y, x + w, y + r, r);
      ctx.lineTo(x + w, y + h);
      ctx.closePath();
    }

    /* 和 object-fit: cover 一个意思 */
    function drawCover(im, dx, dy, dw, dh) {
      var ir = im.width / im.height;
      var dr = dw / dh;
      var sw, sh, sx, sy;
      if (ir > dr) { sh = im.height; sw = sh * dr; sx = (im.width - sw) / 2; sy = 0; }
      else { sw = im.width; sh = sw / dr; sx = 0; sy = (im.height - sh) / 2; }
      ctx.drawImage(im, sx, sy, sw, sh, dx, dy, dw, dh);
    }

    /* 中文没有空格，得按字断行 */
    function wrapText(text, maxWidth) {
      var tokens = String(text).match(/[\u4e00-\u9fff\u3000-\u303f\uff00-\uffef]|[A-Za-z0-9_@.\-:\/'"()\[\]+]+|\s+|[\s\S]/g) || [];
      var out = [];
      var line = '';
      for (var i = 0; i < tokens.length; i++) {
        var t = tokens[i];
        if (t === '\n') { out.push(line); line = ''; continue; }
        var test = line + t;
        if (line && ctx.measureText(test).width > maxWidth) {
          out.push(line);
          line = t.replace(/^\s+/, '');
        } else {
          line = test;
        }
      }
      if (line) out.push(line);
      return out;
    }

    function clipText(text, maxWidth) {
      if (ctx.measureText(text).width <= maxWidth) return text;
      var s = String(text);
      while (s.length && ctx.measureText(s + '…').width > maxWidth) s = s.slice(0, -1);
      return s + '…';
    }

    /* ---------------- 主题色 ---------------- */
    /* canvas 读不到 CSS 变量，得自己取出来，换主题时再取一次 */
    function readTheme() {
      var cs = getComputedStyle(root);
      function v(name, dflt) {
        var x = cs.getPropertyValue(name).trim();
        return x || dflt;
      }
      theme = {
        fg: v('--color_fg', '#1b1b1b'),
        bg: v('--color_bg', '#f4f2ec'),
        bg2: v('--color_bg2', '#ffffff'),
        mid: v('--color_mid', '#d9d4c7'),
        dim: v('--color_dim', 'rgba(27,27,27,.55)'),
        accent: v('--color_theme', '#568203'),
        card: v('--color_card', 'rgba(255,255,255,.72)')
      };
    }

    /* ---------------- 排布与绕回 ---------------- */
    /*
      008 里用的是两个 if 分别往两边推，但位移落在「一个 margin」那么宽的
      区间里时，两个 if 会互相抵消，那张卡就卡住不动了。
      这里改成一次性归一到一个周期内，行为一样但没有那个死区。
      归一到 [-step, period - step)，正好一个周期，网格始终盖得住视口。
    */
    function wrapAxis(v, period, step) {
      v = (v + step) % period;
      if (v < 0) v += period;
      return v - step;
    }

    function layout() {
      var w = wrapEl.clientWidth || 1;
      var h = wrapEl.clientHeight || 1;
      var dpr = Math.min(window.devicePixelRatio || 1, 2);

      canvas.width = Math.max(1, Math.round(w * dpr));
      canvas.height = Math.max(1, Math.round(h * dpr));
      ctx.setTransform(dpr, 0, 0, dpr, 0, 0);

      cols = Math.max(2, Math.ceil(w / STEP_X) + 1);
      rows = Math.max(2, Math.ceil(h / STEP_Y) + 1);
      periodX = cols * STEP_X;
      periodY = rows * STEP_Y;

      cards = [];
      for (var i = 0; i < cols * rows; i++) {
        cards.push({
          col: i % cols,
          row: Math.floor(i / cols),
          friend: i % friends.length,
          x: 0, y: 0
        });
      }
      updatePositions();
      needsDraw = true;
    }

    function updatePositions() {
      for (var i = 0; i < cards.length; i++) {
        var c = cards[i];
        c.x = wrapAxis(c.col * STEP_X + offX, periodX, STEP_X);
        c.y = wrapAxis(c.row * STEP_Y + offY, periodY, STEP_Y);
      }
    }

    /* ---------------- 图片 ---------------- */
    function loadImages() {
      images = friends.map(function (f, i) {
        var slot = { cover: null, avatar: null };
        if (f.cover) {
          var im = new Image();
          im.onload = function () { slot.cover = im; needsDraw = true; };
          im.src = f.cover;
        }
        if (f.avatar) {
          var av = new Image();
          av.onload = function () { slot.avatar = av; needsDraw = true; };
          av.src = f.avatar;
        }
        return slot;
      });
    }

    /* ---------------- 绘制 ---------------- */
    function drawCard(c) {
      var f = friends[c.friend];
      var img = images[c.friend] || {};
      var x = c.x, y = c.y;

      /* 卡片底 */
      roundRectPath(x, y, CARD_W, CARD_H, RADIUS);
      ctx.fillStyle = theme.card;
      ctx.fill();

      /* 封面 */
      ctx.save();
      topRoundPath(x, y, CARD_W, COVER_H, RADIUS);
      ctx.clip();
      if (img.cover) {
        drawCover(img.cover, x, y, CARD_W, COVER_H);
      } else {
        ctx.fillStyle = theme.mid;
        ctx.fillRect(x, y, CARD_W, COVER_H);
      }
      /* 压一层暗角，右上角的标签才看得清 */
      var g = ctx.createLinearGradient(0, y + COVER_H * .3, 0, y + COVER_H);
      g.addColorStop(0, 'rgba(0,0,0,0)');
      g.addColorStop(1, 'rgba(0,0,0,.42)');
      ctx.fillStyle = g;
      ctx.fillRect(x, y, CARD_W, COVER_H);
      ctx.restore();

      /* 标签 */
      if (f.tag) {
        ctx.font = '600 11px ' + FONT;
        ctx.textBaseline = 'middle';
        var tw = ctx.measureText(f.tag).width;
        var pw = tw + 16, ph = 20;
        var px = x + CARD_W - 12 - pw, py = y + 12;
        roundRectPath(px, py, pw, ph, 4);
        ctx.fillStyle = theme.accent;
        ctx.fill();
        ctx.fillStyle = theme.bg;
        ctx.fillText(f.tag, px + 8, py + ph / 2 + .5);
      }

      /* 头像：压在封面下沿 */
      var av = AVATAR;
      var ax = x + 14, ay = y + COVER_H - av / 2;
      ctx.save();
      ctx.beginPath();
      ctx.arc(ax + av / 2, ay + av / 2, av / 2, 0, Math.PI * 2);
      ctx.closePath();
      ctx.fillStyle = theme.bg2;
      ctx.fill();
      ctx.clip();
      if (img.avatar) ctx.drawImage(img.avatar, ax, ay, av, av);
      ctx.restore();

      /* 名字 */
      var tx = ax + av + 12;
      var nameMax = x + CARD_W - 14 - tx;
      ctx.font = '700 15px ' + FONT;
      ctx.textBaseline = 'top';
      ctx.fillStyle = theme.fg;
      ctx.fillText(clipText(f.name || '', nameMax), tx, y + COVER_H + 4);

      /* 简介：两行 */
      ctx.font = '400 12.5px ' + FONT;
      ctx.fillStyle = theme.dim;
      var all = wrapText(f.desc || '', CARD_W - 28);
      var lines = all.slice(0, 2);
      if (all.length > 2) lines[1] = clipText(lines[1] + '…', CARD_W - 28);
      for (var i = 0; i < lines.length; i++) {
        ctx.fillText(lines[i], x + 14, y + COVER_H + 28 + i * 17);
      }

      /* 被指到的那张，描一遍边框 */
      if (c === hovered) {
        var pad = 4;
        var w2 = CARD_W + pad * 2, h2 = CARD_H + pad * 2;
        var per = 2 * (w2 + h2);
        roundRectPath(x - pad, y - pad, w2, h2, RADIUS + pad);
        ctx.save();
        ctx.setLineDash([per * strokeT.v, per]);
        ctx.lineDashOffset = 0;
        ctx.strokeStyle = theme.accent;
        ctx.lineWidth = 2;
        ctx.stroke();
        ctx.restore();
      }
    }

    function draw() {
      var w = wrapEl.clientWidth || 1;
      var h = wrapEl.clientHeight || 1;
      ctx.clearRect(0, 0, w, h);
      for (var i = 0; i < cards.length; i++) {
        var c = cards[i];
        /* 视口外的就不画了 */
        if (c.x > w || c.x + CARD_W < 0 || c.y > h || c.y + CARD_H < 0) continue;
        drawCard(c);
      }
    }

    /* ---------------- 交互 ---------------- */
    function localPoint(e) {
      var b = canvas.getBoundingClientRect();
      return { x: e.clientX - b.left, y: e.clientY - b.top };
    }

    function hitTest(px, py) {
      for (var i = cards.length - 1; i >= 0; i--) {
        var c = cards[i];
        if (px >= c.x && px < c.x + CARD_W && py >= c.y && py < c.y + CARD_H) return c;
      }
      return null;
    }

    function hideHint() {
      if (hint) hint.classList.add('is-hidden');
    }

    function setHovered(card) {
      if (card === hovered) return;
      hovered = card;
      needsDraw = true;

      if (card) {
        if (cursorApi) {
          cursorApi.set(function () {
            var b = canvas.getBoundingClientRect();
            return { left: b.left + card.x, top: b.top + card.y, width: CARD_W, height: CARD_H };
          }, friends[card.friend].name || '友链');
        }
        /* 边框从头描一遍 */
        gsap.killTweensOf(strokeT);
        strokeT.v = 0;
        gsap.to(strokeT, {
          v: 1, duration: .7, ease: EASE_OUT, overwrite: true,
          onUpdate: function () { needsDraw = true; }
        });
      } else if (cursorApi) {
        cursorApi.clear();
      }
    }

    canvas.addEventListener('pointerdown', function (e) {
      dragging = true;
      dragMoved = 0;
      lastPt = { x: e.clientX, y: e.clientY };
      wrapEl.classList.add('is-dragging');
      hideHint();
      if (canvas.setPointerCapture) { try { canvas.setPointerCapture(e.pointerId); } catch (err) { } }
    });

    canvas.addEventListener('pointermove', function (e) {
      if (dragging) {
        var dx = e.clientX - lastPt.x;
        var dy = e.clientY - lastPt.y;
        lastPt = { x: e.clientX, y: e.clientY };
        offX += dx;
        offY += dy;
        dragMoved += Math.abs(dx) + Math.abs(dy);
        updatePositions();
        needsDraw = true;
        return;
      }
      var p = localPoint(e);
      setHovered(hitTest(p.x, p.y));
    });

    function endDrag(e) {
      if (!dragging) return;
      dragging = false;
      wrapEl.classList.remove('is-dragging');
      /* 几乎没挪动，就算点击 */
      if (dragMoved < 6) {
        var p = localPoint(e);
        var hit = hitTest(p.x, p.y);
        if (hit) {
          var f = friends[hit.friend];
          if (f && f.url) window.open(f.url, '_blank', 'noopener');
        }
      }
    }
    canvas.addEventListener('pointerup', endDrag);
    canvas.addEventListener('pointercancel', function () {
      dragging = false;
      wrapEl.classList.remove('is-dragging');
    });
    canvas.addEventListener('pointerleave', function () {
      if (!dragging) setHovered(null);
    });

    /* ---------------- 动起来 ---------------- */
    window.addEventListener('resize', function () {
      layout();
    });

    if (window.IntersectionObserver) {
      new IntersectionObserver(function (entries) {
        visible = entries[0].isIntersecting;
        if (visible) { needsDraw = true; lastT = 0; }
      }, { rootMargin: '120px' }).observe(wrapEl);
    }

    gsap.ticker.add(function (time) {
      var dt = lastT ? Math.min(time - lastT, .05) : 0;
      lastT = time;
      if (!visible) return;

      /* 没人操作的时候自己慢慢漂；鼠标停在卡片上就停住，方便点 */
      if (!reduce && !dragging && !hovered) {
        offX -= DRIFT * dt;
        updatePositions();
        needsDraw = true;
      }
      if (needsDraw) {
        needsDraw = false;
        draw();
      }
    });

    /* ---------------- 起步 ---------------- */
    readTheme();
    loadImages();
    layout();

    return {
      /* 换深浅色之后 canvas 得重新取一次颜色 */
      refresh: function () { readTheme(); needsDraw = true; }
    };
  }

  /* ======================================================================
     转场动画
     ====================================================================== */
  var transitioning = false;

  function transitionParts() {
    var t = document.getElementById('transition');
    if (!t) return null;
    return {
      el: t,
      halves: t.querySelectorAll('.transition_half'),
      bars: t.querySelectorAll('.transition_bar'),
      fold: t.querySelector('.transition_fold')
    };
  }

  /* 进场：CSS 已经把两张纸合上了，这里把它们打开 */
  function openTransition(onDone) {
    var p = transitionParts();
    if (!p) { if (onDone) onDone(); return; }

    if (reduce) {
      root.classList.remove('enter-transition');
      if (onDone) onDone();
      return;
    }

    gsap.timeline({
      onComplete: function () {
        root.classList.remove('enter-transition');
        p.el.classList.remove('is-visible', 'is-active');
        gsap.set(p.halves, { clearProps: 'height' });
        gsap.set(p.bars, { clearProps: 'transform' });
        gsap.set(p.fold, { clearProps: 'transform' });
        if (onDone) onDone();
      }
    })
      .to(p.bars, {
        scaleY: 0, duration: .5, ease: EASE_OUT,
        stagger: { from: 'edges', each: .012 }
      }, 0)
      .to(p.fold, { scale: 0, duration: .6, ease: EASE_OUT }, 0)
      .to(p.halves, { height: 0, duration: .65, ease: EASE_INOUT }, .1);
  }

  /* 离场：合上，然后跳走 */
  function leaveTo(url) {
    if (transitioning) return;
    transitioning = true;

    var p = transitionParts();
    if (!p || reduce) { window.location.href = url; return; }

    p.el.classList.add('is-visible', 'is-active');
    lockScroll(true);

    gsap.timeline({
      onComplete: function () { window.location.href = url; }
    })
      .set(p.halves, { height: 0 })
      .set(p.bars, { scaleY: 0 })
      .set(p.fold, { scale: 0 })
      .to(p.halves, { height: '50%', duration: .6, ease: EASE_INOUT }, 0)
      .to(p.bars, {
        scaleY: 1, duration: .5, ease: EASE_OUT,
        stagger: { from: 'random', each: .012 }
      }, .1)
      .to(p.fold, { scale: 1, duration: .5, ease: EASE_OUT }, .15);
  }

  /* ======================================================================
     开场动画
     ====================================================================== */
  function initSplash() {
    var splash = document.getElementById('splash');
    if (!splash) return null;

    var logo = document.getElementById('nav-logo');
    var logoImg = logo ? logo.querySelector('img') : null;
    var nav = document.getElementById('main-navigation');
    var ring = splash.querySelector('.splash_ring');
    var middle = splash.querySelector('.splash_middle');
    var progress = splash.querySelector('.splash_progress');
    var button = splash.querySelector('.splash_button');
    var percentEl = document.getElementById('splash-percent');
    var waveLines = gsap.utils.toArray('.splash_wave_line', splash);
    var waveBars = gsap.utils.toArray('.splash_wave_bar', splash);
    var TOTAL = waveLines.length || 1;

    /* ---- 头像先在正中间、放大 ---- */
    if (logo) logo.classList.add('is-splash');
    gsap.set(logo, { clearProps: 'transform' });
    var natural = logo ? logo.getBoundingClientRect() : null;
    var ringBox = ring ? ring.getBoundingClientRect() : null;

    if (logo && natural && ringBox && natural.width) {
      var size = Math.max(96, ringBox.width * 0.44);
      var scale = size / natural.width;
      gsap.set(logo, {
        x: window.innerWidth / 2 - (natural.left + natural.width / 2),
        y: window.innerHeight / 2 - (natural.top + natural.height / 2),
        scale: scale,
        transformOrigin: '50% 50%'
      });
    }
    if (logoImg) gsap.set(logoImg, { opacity: 0, scale: .5 });
    if (middle) gsap.set(middle, { opacity: 0, y: 12 });
    if (ring) gsap.set(ring, { opacity: 0 });
    gsap.set('.nav_item_label > span', { yPercent: -165 });

    /* ---- 声波振幅：预生成几帧来回切，参考站点就是这么干的 ---- */
    var frames = buildWaveFrames(waveBars.length, 6);
    var frameIndex = 0;
    var frameTimer = window.setInterval(function () {
      frameIndex = (frameIndex + 1) % frames.length;
      var f = frames[frameIndex];
      for (var i = 0; i < waveBars.length; i++) waveBars[i].style.setProperty('--s', f[i]);
    }, 300);

    /* ---- 加载进度：声波按进度顺时针画出来 ---- */
    var prog = { v: 0 };
    var armed = false;
    var entered = false;

    gsap.to(prog, {
      v: 100,
      duration: 1.9,
      ease: 'power2.inOut',
      onUpdate: function () {
        var p = prog.v;
        if (percentEl) percentEl.textContent = Math.round(p) + '%';
        for (var i = 0; i < waveLines.length; i++) {
          var hidden = (i / TOTAL) * 100 > p;
          if (hidden === waveLines[i].classList.contains('is-hidden')) continue;
          waveLines[i].classList.toggle('is-hidden', hidden);
          gsap.set(waveLines[i], { scaleY: hidden ? 0 : 1 });
        }
      },
      onComplete: function () {
        window.clearInterval(frameTimer);

        gsap.timeline()
          /* 进度条升起，换成「进入主页」 */
          .to([progress, button], { yPercent: -100, duration: .8, ease: EASE_INOUT }, 0)
          /* 声波收掉 */
          .to(waveLines, {
            scaleY: 0, duration: .5, ease: EASE_OUT,
            stagger: { from: 'random', each: .004 }
          }, 0)
          /* 圆环亮起来 */
          .to(ring, { opacity: 1, duration: .5, ease: EASE_OUT }, .2)
          /* 头像落进圆环 —— 用户看到的就是这一下 */
          .fromTo(logoImg,
            { opacity: 0, scale: .5 },
            { opacity: 1, scale: 1, duration: 1, ease: EASE_INOUT }, .55)
          .fromTo(middle,
            { opacity: 0, y: 12 },
            { opacity: 1, y: 0, duration: .6, ease: EASE_OUT }, .9)
          .call(function () {
            armed = true;
            splash.classList.add('is-ready');
          });
      }
    });

    /* ---- 点击进入 ---- */
    function onKey(e) {
      if (e.key === 'Enter' || e.key === ' ') {
        e.preventDefault();
        enter();
      }
    }

    function enter() {
      if (!armed || entered) return;
      entered = true;
      window.removeEventListener('keydown', onKey);
      splash.removeEventListener('click', enter);
      try { sessionStorage.setItem('blog-splash', '1'); } catch (e) { }

      gsap.timeline({
        onComplete: function () {
          /* 开场结束：卸掉开场层，之后的换页交给转场动画 */
          splashActive = false;
          root.classList.remove('has-splash');
          if (logo) logo.classList.remove('is-splash');
          gsap.set(logo, { clearProps: 'transform' });
          gsap.set('.nav_item_label > span', { clearProps: 'transform' });
          gsap.set(nav, { clearProps: 'clipPath' });
          splash.classList.add('is-done');
          lockScroll(false);
          introPlay();
        }
      })
        /* 1) 开场层淡出，露出下面的页面 */
        .to(splash, { backgroundColor: 'rgba(0, 0, 0, 0)', duration: .5, ease: EASE_OUT }, 0)
        .to([ring, middle], { opacity: 0, duration: .35, ease: EASE_OUT }, 0)
        /* 2) 头像平移到左上角 */
        .to(logo, { x: 0, y: 0, scale: 1, duration: 1.05, ease: EASE_INOUT }, .05)
        /* 3) 毛玻璃状态栏以头像为起点向右弹出 */
        .to(nav, {
          clipPath: 'polygon(0% 0%, 100% 0%, 100% 100%, 0% 100%)',
          duration: 1,
          ease: EASE_INOUT
        }, .55)
        /* 4) 栏目文字逐行落下 */
        .to('.nav_item_label > span', {
          yPercent: 0, duration: .8, ease: EASE_OUT, stagger: .1
        }, .95);
    }

    splash.addEventListener('click', enter);
    /* 头像本身是 <a href="/">，开场期间点它也算「进入主页」 */
    if (logo) {
      logo.addEventListener('click', function (e) {
        if (!splashActive) return;
        e.preventDefault();
        enter();
      });
    }
    window.addEventListener('keydown', onKey);
    splashActive = true;
    lockScroll(true);

    return { enter: enter };
  }

  /* 把振幅做成一圈错落的方波，循环播放就有“在动”的感觉 */
  function buildWaveFrames(n, count) {
    var frames = [];
    for (var f = 0; f < count; f++) {
      var arr = [];
      for (var i = 0; i < n; i++) {
        var t = (i / n) * Math.PI * 2;
        var v = Math.sin(t * 3 + f * 1.7) * Math.sin(t * 7 - f * .9) * Math.cos(t * 1.3 + f);
        arr.push(Math.max(.08, Math.min(1, Math.abs(v))).toFixed(2));
      }
      frames.push(arr);
    }
    return frames;
  }

  /* ======================================================================
     导航、主题、锚点
     ====================================================================== */
  function initNav() {
    var btn = document.getElementById('theme-toggle');
    if (btn) {
      btn.addEventListener('click', function () {
        var next = root.getAttribute('data-theme') === 'dark' ? 'light' : 'dark';
        root.setAttribute('data-theme', next);
        try { localStorage.setItem('blog-theme', next); } catch (e) { }
        /* canvas 上的颜色是画上去的，换了主题得让它重取一次 */
        if (friendWall) friendWall.refresh();
        window.ScrollTrigger.refresh();
      });
    }
  }

  function scrollToAnchor(hash) {
    var target = document.querySelector(hash);
    if (!target) return;
    if (lenis) {
      lenis.scrollTo(target, { offset: -90 });
    } else {
      window.scrollTo({ top: target.getBoundingClientRect().top + window.pageYOffset - 90, behavior: 'smooth' });
    }
  }

  function initLinks() {
    document.addEventListener('click', function (e) {
      if (e.defaultPrevented || e.button !== 0) return;
      if (e.metaKey || e.ctrlKey || e.shiftKey || e.altKey) return;

      var a = e.target && e.target.closest ? e.target.closest('a') : null;
      if (!a) return;
      if (a.target === '_blank' || a.hasAttribute('download')) return;

      var href = a.getAttribute('href');
      if (!href) return;

      /* 页内锚点：平滑滚过去 */
      if (href.charAt(0) === '#') {
        e.preventDefault();
        scrollToAnchor(href);
        return;
      }

      var url;
      try { url = new URL(a.href, window.location.href); } catch (err) { return; }
      if (url.origin !== window.location.origin) return;          /* 外链不接管 */
      if (url.pathname === window.location.pathname) return;      /* 当前页不接管 */
      if (!/^https?:$/.test(url.protocol)) return;

      /* 开场期间头像浮在中间，点它就是「进入主页」，不该跳走 */
      if (splashActive) {
        e.preventDefault();
        return;
      }

      if (reduce) return;                                          /* 减少动效就直接跳 */
      e.preventDefault();
      leaveTo(url.href);
    });
  }

  /* 浏览器后退回来时可能带着上一次的遮罩状态，清一下 */
  window.addEventListener('pageshow', function (e) {
    if (!e.persisted) return;
    transitioning = false;
    var p = transitionParts();
    if (p) p.el.classList.remove('is-visible', 'is-active');
    root.classList.remove('enter-transition');
    lockScroll(false);
  });

  /* ======================================================================
     启动
     ====================================================================== */
  function boot() {
    initScroll();
    initNav();
    initLinks();
    initCursor();
    prepareHiddenStates();

    /* 友链照片墙。canvas 起不来（老浏览器、数据坏掉）就退回成普通列表 */
    friendWall = initFriendWall();
    if (!friendWall) root.classList.add('no-friendwall');

    /* 只有首页第一次进来才播开场；同一次会话里再回首页就直接走转场 */
    var splash = root.classList.contains('has-splash') ? initSplash() : null;

    if (!splash) {
      /* 这次不播开场：把开场层彻底收起来，别让它挡住页面 */
      var splashEl = document.getElementById('splash');
      if (splashEl) splashEl.classList.add('is-done');
    }

    if (splash) {
      /* 等用户点「进入主页」，再跑页面里的动画 */
      return;
    }

    /* 其它页面：打开转场遮罩，然后跑动画 */
    if (root.classList.contains('enter-transition')) {
      lockScroll(true);
      openTransition(function () {
        lockScroll(false);
        introPlay();
      });
    } else {
      introPlay();
    }
  }

  if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', boot);
  } else {
    boot();
  }

  /* 图片/字体加载完版式可能变，重新量一次 */
  window.addEventListener('load', function () {
    window.ScrollTrigger.refresh();
  });
})();
