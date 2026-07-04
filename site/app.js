(function () {
  // Host-side HTTPS enforcement still belongs in Cloudflare/GitHub Pages.
  // This fallback only upgrades real browser visits that reach the static app
  // over plain HTTP while that host-side setting is being verified.
  function enforceCanonicalHttps() {
    var host = window.location.hostname;
    if (
      window.location.protocol === "http:" &&
      (host === "nosuchmachine.net" || host === "www.nosuchmachine.net")
    ) {
      window.location.replace(
        "https://nosuchmachine.net" +
          window.location.pathname +
          window.location.search +
          window.location.hash
      );
    }
  }
  enforceCanonicalHttps();

  // Gallery lightbox
  function setupLightbox() {
    var figures = document.querySelectorAll("main figure");
    if (!figures.length) return;

    var lightbox = document.createElement("div");
    lightbox.className = "lightbox";
    lightbox.setAttribute("role", "dialog");
    lightbox.setAttribute("aria-modal", "true");
    lightbox.setAttribute("aria-hidden", "true");
    lightbox.setAttribute("aria-label", "Image preview");
    lightbox.innerHTML = '<button class="lightbox-close" aria-label="Close">&times;</button><img src="" alt="">';
    document.body.appendChild(lightbox);

    var lightboxImg = lightbox.querySelector("img");
    var closeBtn = lightbox.querySelector(".lightbox-close");
    var pageRegions = Array.prototype.slice.call(document.querySelectorAll(".site-header, main, .site-footer"));
    var lastActiveElement = null;
    closeBtn.setAttribute("tabindex", "-1");

    function setPageHidden(hidden) {
      pageRegions.forEach(function (region) {
        if (hidden) {
          region.setAttribute("aria-hidden", "true");
          region.setAttribute("inert", "");
        } else {
          region.removeAttribute("aria-hidden");
          region.removeAttribute("inert");
        }
      });
    }

    function openFigure(figure) {
      var img = figure.querySelector("img");
      if (img) {
        lastActiveElement = document.activeElement;
        lightboxImg.src = img.src;
        lightboxImg.alt = img.alt;
        lightbox.setAttribute("aria-hidden", "false");
        closeBtn.removeAttribute("tabindex");
        lightbox.classList.add("is-active");
        document.body.style.overflow = "hidden";
        closeBtn.focus({ preventScroll: true });
        window.requestAnimationFrame(function () {
          closeBtn.focus({ preventScroll: true });
        });
        setPageHidden(true);
      }
    }

    figures.forEach(function (figure) {
      var img = figure.querySelector("img");
      var caption = figure.querySelector("figcaption");
      var label = caption ? caption.textContent : img ? img.alt : "image";
      figure.setAttribute("role", "button");
      figure.setAttribute("tabindex", "0");
      figure.setAttribute("aria-label", "Open larger view: " + label.trim());
      figure.addEventListener("click", function () {
        openFigure(figure);
      });
      figure.addEventListener("keydown", function (e) {
        if (e.key === "Enter" || e.key === " ") {
          e.preventDefault();
          openFigure(figure);
        }
      });
    });

    function closeLightbox() {
      lightbox.classList.remove("is-active");
      lightbox.setAttribute("aria-hidden", "true");
      closeBtn.setAttribute("tabindex", "-1");
      setPageHidden(false);
      document.body.style.overflow = "";
      if (lastActiveElement && document.contains(lastActiveElement) && typeof lastActiveElement.focus === "function") {
        lastActiveElement.focus();
      }
      lastActiveElement = null;
    }

    closeBtn.addEventListener("click", closeLightbox);
    lightbox.addEventListener("click", function (e) {
      if (e.target === lightbox) closeLightbox();
    });
    document.addEventListener("keydown", function (e) {
      if (e.key === "Escape" && lightbox.classList.contains("is-active")) {
        closeLightbox();
      }
      if (e.key === "Tab" && lightbox.classList.contains("is-active")) {
        e.preventDefault();
        closeBtn.focus({ preventScroll: true });
      }
    });
  }
  setupLightbox();

  // Copy buttons
  var buttons = document.querySelectorAll("[data-copy]");

  buttons.forEach(function (button) {
    button.addEventListener("click", function () {
      var value = button.getAttribute("data-copy") || "";

      function showCopied() {
        var original = button.textContent;
        button.textContent = "Copied";
        window.setTimeout(function () {
          button.textContent = original;
        }, 1600);
      }

      function showManualCopy() {
        var original = button.textContent;
        var card = button.closest(".command-card");
        var code = card ? card.querySelector("code") : null;

        if (code && window.getSelection && document.createRange) {
          var range = document.createRange();
          range.selectNodeContents(code);
          var selection = window.getSelection();
          selection.removeAllRanges();
          selection.addRange(range);
        }

        button.textContent = "Selected";
        window.setTimeout(function () {
          button.textContent = original;
        }, 1800);
      }

      function fallbackCopy() {
        var textArea = document.createElement("textarea");
        textArea.value = value;
        textArea.setAttribute("readonly", "readonly");
        textArea.style.position = "fixed";
        textArea.style.top = "0";
        textArea.style.left = "0";
        textArea.style.opacity = "0";
        document.body.appendChild(textArea);
        textArea.focus();
        textArea.select();
        textArea.setSelectionRange(0, value.length);

        try {
          if (document.execCommand("copy")) {
            showCopied();
          } else {
            showManualCopy();
          }
        } catch (error) {
          showManualCopy();
        } finally {
          document.body.removeChild(textArea);
        }
      }

      if (navigator.clipboard && navigator.clipboard.writeText) {
        navigator.clipboard.writeText(value).then(showCopied, fallbackCopy);
        return;
      }

      fallbackCopy();
    });
  });

  function query(selector) {
    return document.querySelector(selector);
  }

  function all(selector) {
    return Array.prototype.slice.call(document.querySelectorAll(selector));
  }

  function setupNavToggle() {
    var header = query("[data-header]");
    var toggle = query(".nav-toggle");
    var nav = query("#site-nav");
    if (!header || !toggle || !nav) {
      return;
    }

    function setOpen(open) {
      header.classList.toggle("nav-open", open);
      toggle.setAttribute("aria-expanded", open ? "true" : "false");
    }

    toggle.addEventListener("click", function () {
      setOpen(!header.classList.contains("nav-open"));
    });

    nav.addEventListener("click", function (event) {
      if (event.target.closest("a")) {
        setOpen(false);
      }
    });

    document.addEventListener("keydown", function (event) {
      if (event.key === "Escape" && header.classList.contains("nav-open")) {
        setOpen(false);
        toggle.focus();
      }
    });

    var desktopQuery = window.matchMedia("(min-width: 981px)");
    function handleChange(event) {
      if (event.matches) {
        setOpen(false);
      }
    }
    if (desktopQuery.addEventListener) {
      desktopQuery.addEventListener("change", handleChange);
    } else if (desktopQuery.addListener) {
      desktopQuery.addListener(handleChange);
    }
  }

  function setupHeaderState() {
    var header = query("[data-header]");
    if (!header) {
      return;
    }
    var ticking = false;
    function update() {
      header.classList.toggle("is-scrolled", window.scrollY > 8);
      ticking = false;
    }
    window.addEventListener("scroll", function () {
      if (!ticking) {
        ticking = true;
        window.requestAnimationFrame(update);
      }
    }, { passive: true });
    update();
  }

  function setupScrollSpy() {
    var links = all(".site-nav a[href^='#']");
    if (!links.length || !("IntersectionObserver" in window)) {
      return;
    }
    var linkById = {};
    var sections = [];
    links.forEach(function (link) {
      var id = link.getAttribute("href").slice(1);
      var section = id ? document.getElementById(id) : null;
      if (section) {
        linkById[id] = link;
        sections.push(section);
      }
    });

    function setCurrent(id) {
      links.forEach(function (link) {
        var active = link === linkById[id];
        if (active) {
          link.setAttribute("aria-current", "true");
        } else {
          link.removeAttribute("aria-current");
        }
      });
    }

    var visible = {};
    var observer = new IntersectionObserver(function (entries) {
      entries.forEach(function (entry) {
        visible[entry.target.id] = entry.isIntersecting ? entry.intersectionRatio : 0;
      });
      var bestId = null;
      var bestRatio = 0;
      Object.keys(visible).forEach(function (id) {
        if (visible[id] > bestRatio) {
          bestRatio = visible[id];
          bestId = id;
        }
      });
      if (bestId) {
        setCurrent(bestId);
      }
    }, { rootMargin: "-45% 0px -45% 0px", threshold: [0, 0.25, 0.5, 1] });

    sections.forEach(function (section) {
      observer.observe(section);
    });
  }

  // ===== Cryptographic observatory =====
  function withCommasJs(value) {
    return String(value).replace(/\B(?=(\d{3})+(?!\d))/g, ",");
  }

  function padLeft(value, width) {
    var text = String(value);
    while (text.length < width) {
      text = "0" + text;
    }
    return text;
  }

  function escapeText(value) {
    return String(value).replace(/[&<>]/g, function (character) {
      if (character === "&") return "&amp;";
      if (character === "<") return "&lt;";
      return "&gt;";
    });
  }

  function prefersReducedMotion() {
    return (
      window.matchMedia &&
      window.matchMedia("(prefers-reduced-motion: reduce)").matches
    );
  }

  function setFieldText(selector, value) {
    var element = query(selector);
    if (element && value !== null && value !== undefined) {
      element.textContent = value;
    }
  }

  function setupObservatoryGauges() {
    all("[data-gauge]").forEach(function (gauge) {
      var value = parseFloat(gauge.getAttribute("data-gauge-value"));
      var max = parseFloat(gauge.getAttribute("data-gauge-max"));
      var arc = gauge.querySelector("[data-gauge-arc]");
      if (!arc || !isFinite(value) || !isFinite(max) || max <= 0) {
        return;
      }
      var ratio = Math.max(0, Math.min(1, value / max));
      arc.style.setProperty("--p", ratio.toFixed(5));
    });
  }

  function animateObservatoryCounters(reduce) {
    all("[data-count-to]").forEach(function (element) {
      var target = parseInt(element.getAttribute("data-count-to"), 10);
      if (!isFinite(target)) {
        return;
      }
      if (reduce) {
        element.textContent = withCommasJs(target);
        return;
      }
      var duration = 1500;
      var start = null;
      function frame(timestamp) {
        if (start === null) {
          start = timestamp;
        }
        var progress = Math.min(1, (timestamp - start) / duration);
        var eased = 1 - Math.pow(1 - progress, 3);
        element.textContent = withCommasJs(Math.round(target * eased));
        if (progress < 1) {
          window.requestAnimationFrame(frame);
        } else {
          element.textContent = withCommasJs(target);
        }
      }
      window.requestAnimationFrame(frame);
    });
  }

  function setupObservatoryClock() {
    var clock = query("[data-observatory-clock]");
    var tick = query("[data-observatory-tick]");
    if (!clock && !tick) {
      return;
    }
    var count = 0;
    function update() {
      if (clock) {
        var now = new Date();
        clock.textContent =
          padLeft(now.getUTCHours(), 2) +
          ":" +
          padLeft(now.getUTCMinutes(), 2) +
          ":" +
          padLeft(now.getUTCSeconds(), 2);
      }
      if (tick) {
        count += 1;
        tick.textContent = padLeft(count, 7);
      }
    }
    update();
    window.setInterval(update, 1000);
  }

  function setupDigestStream(reduce) {
    var element = query("[data-digest-stream]");
    if (!element || reduce) {
      return;
    }
    var text = element.textContent;
    if (!text) {
      return;
    }
    var windowSize = 6;
    var position = 0;
    function step() {
      var before = text.slice(0, position);
      var live = text.slice(position, position + windowSize);
      var after = text.slice(position + windowSize);
      element.innerHTML =
        escapeText(before) +
        '<span class="digest-live">' +
        escapeText(live) +
        "</span>" +
        escapeText(after);
      position = (position + windowSize) % text.length;
    }
    step();
    window.setInterval(step, 900);
  }

  function setupObservatoryScope(reduce) {
    var canvas = query("[data-observatory-scope]");
    if (!canvas || !canvas.getContext) {
      return;
    }
    var ctx = canvas.getContext("2d");
    var dpr = window.devicePixelRatio || 1;
    var blips = [
      { a: 0.7, r: 0.34 },
      { a: 2.2, r: 0.64 },
      { a: 3.7, r: 0.27 },
      { a: 5.0, r: 0.72 },
      { a: 5.8, r: 0.48 }
    ];

    function resize() {
      var rect = canvas.getBoundingClientRect();
      canvas.width = Math.max(1, Math.floor(rect.width * dpr));
      canvas.height = Math.max(1, Math.floor(rect.height * dpr));
    }
    resize();
    window.addEventListener("resize", resize, { passive: true });

    function draw(angle) {
      var w = canvas.width;
      var h = canvas.height;
      var cx = w * 0.8;
      var cy = h * 0.52;
      var maxR = Math.max(w, h) * 0.5;
      ctx.clearRect(0, 0, w, h);

      ctx.lineWidth = dpr;
      ctx.strokeStyle = "rgba(134, 184, 189, 0.16)";
      for (var i = 1; i <= 4; i += 1) {
        ctx.beginPath();
        ctx.arc(cx, cy, (maxR * i) / 4, 0, Math.PI * 2);
        ctx.stroke();
      }
      ctx.beginPath();
      ctx.moveTo(cx - maxR, cy);
      ctx.lineTo(cx + maxR, cy);
      ctx.moveTo(cx, cy - maxR);
      ctx.lineTo(cx, cy + maxR);
      ctx.stroke();

      ctx.save();
      ctx.translate(cx, cy);
      ctx.rotate(angle);
      var wedge = ctx.createLinearGradient(0, 0, maxR, 0);
      wedge.addColorStop(0, "rgba(134, 184, 189, 0.22)");
      wedge.addColorStop(1, "rgba(134, 184, 189, 0)");
      ctx.fillStyle = wedge;
      ctx.beginPath();
      ctx.moveTo(0, 0);
      ctx.lineTo(maxR, -maxR * 0.16);
      ctx.lineTo(maxR, 0);
      ctx.closePath();
      ctx.fill();
      ctx.strokeStyle = "rgba(134, 184, 189, 0.5)";
      ctx.lineWidth = 1.4 * dpr;
      ctx.beginPath();
      ctx.moveTo(0, 0);
      ctx.lineTo(maxR, 0);
      ctx.stroke();
      ctx.restore();

      for (var b = 0; b < blips.length; b += 1) {
        var blip = blips[b];
        var delta = Math.abs(((angle - blip.a) % (Math.PI * 2) + Math.PI * 2) % (Math.PI * 2));
        if (delta > Math.PI) {
          delta = Math.PI * 2 - delta;
        }
        var bright = Math.max(0, 1 - delta * 1.6);
        var bx = cx + Math.cos(blip.a) * maxR * blip.r;
        var by = cy + Math.sin(blip.a) * maxR * blip.r;
        ctx.beginPath();
        ctx.arc(bx, by, (2 + bright * 2.4) * dpr, 0, Math.PI * 2);
        ctx.fillStyle = "rgba(143, 186, 137, " + (0.12 + bright * 0.66).toFixed(3) + ")";
        ctx.fill();
      }
    }

    if (reduce) {
      draw(-0.6);
      return;
    }

    var angle = 0;
    function loop() {
      angle += 0.012;
      draw(angle);
      window.requestAnimationFrame(loop);
    }
    window.requestAnimationFrame(loop);
  }

  function refreshObservatoryFeed() {
    var feed = query("[data-observatory-feed]");
    function markStale() {
      if (feed) {
        feed.textContent = "cached";
        feed.setAttribute("data-state", "stale");
      }
    }
    if (!window.fetch) {
      markStale();
      return;
    }
    var endpoints = [
      "daylight-status.json",
      "aperture-status.json",
      "daylight-v20-aperture-singularity-status.json"
    ];
    Promise.all(
      endpoints.map(function (url) {
        return fetch(url, { cache: "no-store" })
          .then(function (response) {
            return response.ok ? response.json() : null;
          })
          .catch(function () {
            return null;
          });
      })
    ).then(function (results) {
      var daylight = results[0];
      var aperture = results[1];
      var v20 = results[2];
      var live = Boolean(daylight && aperture && v20);
      if (feed) {
        feed.textContent = live ? "nominal" : "cached";
        feed.setAttribute("data-state", live ? "live" : "stale");
      }
      if (daylight) {
        setFieldText('[data-field="v17-weakest"]', daylight.weakest_field);
      }
      if (aperture) {
        setFieldText('[data-field="hosted-diff"]', aperture.hosted_artifact_diff);
        setFieldText('[data-field="artifact-count"]', aperture.public_artifact_file_count);
      }
      if (v20) {
        setFieldText(
          '[data-field="external-count"]',
          v20.external_evidence_required_count + " pending"
        );
        var omega = String(v20.omega_eff);
        setFieldText('[data-field="v20-omega"]', omega.slice(0, 12) + "…");
      }
    });
  }

  // Committed evidence digests the site already publishes. Matching one of
  // these confirms a downloaded artifact is byte-identical to the reviewed one.
  var KNOWN_DIGESTS = {
    "716a6a2f845ef9f5c8ae1493474db1ec653fdb09a478089fd144b09c4fd04de9":
      "official Wuci-Ji emblem (assets/wuci-ji-official-emblem.jpg)",
    "9109e7d9364f305a0618e6f5d810f3dd665d995e5c56f9d0ccc8d01875b9eec0":
      "Aperture Bastion capsule digest",
    "dd69f30f3ed099032fe3c16e1d55b2c269f8dc5e1c056537ee9d9a8c8cdf62e5":
      "Daylight v20 Aperture Singularity capsule digest",
    "6debccd2631146bead454d475789060d3aad50ef2d7b18b60d7960ce67bddd3d":
      "Daylight v17 scorecard digest",
    "d191c651b963806015e1c779fcf72ab7d84cac9c0090f5beeb38a108e3329878":
      "Aperture public-artifact firewall profile digest"
  };

  function bytesToHex(buffer) {
    var view = new Uint8Array(buffer);
    var hex = "";
    for (var i = 0; i < view.length; i += 1) {
      var part = view[i].toString(16);
      hex += part.length < 2 ? "0" + part : part;
    }
    return hex;
  }

  function formatBytes(count) {
    if (!isFinite(count)) {
      return "—";
    }
    if (count < 1024) {
      return count + " B";
    }
    var units = ["KB", "MB", "GB"];
    var value = count / 1024;
    var unit = 0;
    while (value >= 1024 && unit < units.length - 1) {
      value /= 1024;
      unit += 1;
    }
    return value.toFixed(value < 10 ? 2 : 1) + " " + units[unit];
  }

  function readArrayBuffer(file) {
    if (file.arrayBuffer) {
      return file.arrayBuffer();
    }
    return new Promise(function (resolve, reject) {
      var reader = new FileReader();
      reader.onload = function () {
        resolve(reader.result);
      };
      reader.onerror = function () {
        reject(reader.error || new Error("read failed"));
      };
      reader.readAsArrayBuffer(file);
    });
  }

  function setupEvidenceVerifier() {
    var root = query("[data-verifier]");
    if (!root) {
      return;
    }
    var input = query("[data-verifier-input]");
    var drop = query("[data-verifier-drop]");
    var demo = query("[data-verifier-demo]");
    var nameEl = query("[data-verifier-name]");
    var sizeEl = query("[data-verifier-size]");
    var digestEl = query("[data-verifier-digest]");
    var result = query("[data-verifier-result]");
    var badge = query("[data-verifier-badge]");
    var message = query("[data-verifier-message]");
    var expected = query("[data-verifier-expected]");
    var lastHex = "";

    function digestAvailable() {
      return Boolean(
        window.crypto &&
          window.crypto.subtle &&
          typeof window.crypto.subtle.digest === "function"
      );
    }

    function setState(state, badgeText, text) {
      if (result) {
        result.setAttribute("data-state", state);
      }
      if (badge) {
        badge.textContent = badgeText;
      }
      if (message) {
        message.textContent = text;
      }
    }

    function evaluate(hex) {
      lastHex = hex;
      var want = (expected && expected.value ? expected.value : "")
        .trim()
        .toLowerCase();
      if (want) {
        if (!/^[0-9a-f]{64}$/.test(want)) {
          setState("info", "check", "Expected value is not a 64-character SHA-256 hex digest.");
          return;
        }
        if (hex === want) {
          setState("match", "match", "Digest matches the value you pasted.");
        } else {
          setState("mismatch", "mismatch", "Digest does not match the value you pasted.");
        }
        return;
      }
      if (KNOWN_DIGESTS[hex]) {
        setState("match", "match", "Matches committed evidence: " + KNOWN_DIGESTS[hex] + ".");
      } else {
        setState("info", "computed", "Digest computed locally. No committed evidence entry matches this file.");
      }
    }

    function digestBuffer(buffer) {
      return window.crypto.subtle.digest("SHA-256", buffer).then(function (out) {
        var hex = bytesToHex(out);
        if (digestEl) {
          digestEl.textContent = hex;
        }
        evaluate(hex);
      });
    }

    function hashFile(file) {
      if (!file) {
        return;
      }
      if (!digestAvailable()) {
        setState("error", "unsupported", "This browser does not expose SHA-256 to the page.");
        return;
      }
      if (nameEl) {
        nameEl.textContent = file.name || "(unnamed file)";
      }
      if (sizeEl) {
        sizeEl.textContent = formatBytes(file.size);
      }
      if (digestEl) {
        digestEl.textContent = "…";
      }
      setState("working", "hashing", "Computing SHA-256 on your device — nothing is uploaded.");
      readArrayBuffer(file)
        .then(digestBuffer)
        .catch(function () {
          setState("error", "error", "Could not read this file in the browser.");
        });
    }

    if (!digestAvailable()) {
      setState("error", "unsupported", "This browser does not expose SHA-256 to the page.");
      if (input) {
        input.disabled = true;
      }
      if (demo) {
        demo.disabled = true;
      }
      return;
    }

    if (input) {
      input.addEventListener("change", function () {
        if (input.files && input.files[0]) {
          hashFile(input.files[0]);
        }
      });
    }

    if (drop) {
      ["dragenter", "dragover"].forEach(function (name) {
        drop.addEventListener(name, function (event) {
          event.preventDefault();
          drop.classList.add("is-dragover");
        });
      });
      ["dragleave", "dragend", "drop"].forEach(function (name) {
        drop.addEventListener(name, function (event) {
          event.preventDefault();
          drop.classList.remove("is-dragover");
        });
      });
      drop.addEventListener("drop", function (event) {
        var files = event.dataTransfer && event.dataTransfer.files;
        if (files && files[0]) {
          hashFile(files[0]);
        }
      });
    }

    if (expected) {
      expected.addEventListener("input", function () {
        if (lastHex) {
          evaluate(lastHex);
        }
      });
    }

    if (demo) {
      demo.addEventListener("click", function () {
        if (!window.fetch) {
          setState("error", "error", "This browser cannot fetch the served emblem.");
          return;
        }
        if (nameEl) {
          nameEl.textContent = "wuci-ji-official-emblem.jpg";
        }
        setState("working", "hashing", "Hashing the served emblem locally — nothing is uploaded.");
        fetch("assets/wuci-ji-official-emblem.jpg", { cache: "no-store" })
          .then(function (response) {
            if (!response.ok) {
              throw new Error("fetch failed");
            }
            return response.arrayBuffer();
          })
          .then(function (buffer) {
            if (sizeEl) {
              sizeEl.textContent = formatBytes(buffer.byteLength);
            }
            return digestBuffer(buffer);
          })
          .catch(function () {
            setState("error", "error", "Could not fetch the served emblem.");
          });
      });
    }
  }

  function setupObservatory() {
    if (!query("[data-observatory]")) {
      return;
    }
    var reduce = prefersReducedMotion();
    setupObservatoryGauges();
    animateObservatoryCounters(reduce);
    setupObservatoryClock();
    setupDigestStream(reduce);
    setupObservatoryScope(reduce);
    refreshObservatoryFeed();
    setupEvidenceVerifier();
  }

  setupNavToggle();
  setupHeaderState();
  setupScrollSpy();
  setupObservatory();
})();
