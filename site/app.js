(function () {
  // Host-side HTTPS enforcement belongs in the canonical Cloudflare deployment.
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

  function setupPageShell() {
    var main = document.querySelector("main");
    if (main && !main.id) {
      main.id = "main-content";
    }

    if (main && !document.querySelector(".skip-link")) {
      var skipLink = document.createElement("a");
      skipLink.className = "skip-link";
      skipLink.href = "#main-content";
      skipLink.textContent = "Skip to content";
      document.body.insertBefore(skipLink, document.body.firstChild);
    }

    var header = document.querySelector(".site-header");
    var nav = header ? header.querySelector(".site-nav") : null;
    if (header && nav) {
      header.setAttribute("data-header", "");
      if (!nav.id) {
        nav.id = "site-nav";
      }
      if (!header.querySelector(".nav-toggle")) {
        var toggle = document.createElement("button");
        toggle.className = "nav-toggle";
        toggle.type = "button";
        toggle.setAttribute("aria-controls", nav.id);
        toggle.setAttribute("aria-expanded", "false");
        toggle.setAttribute("aria-label", "Toggle navigation menu");
        var bars = document.createElement("span");
        bars.className = "nav-toggle-bars";
        bars.setAttribute("aria-hidden", "true");
        toggle.appendChild(bars);
        header.appendChild(toggle);
      }
    }

    if (main && !document.querySelector(".site-footer")) {
      var footer = document.createElement("footer");
      footer.className = "site-footer nsm-footer";
      footer.innerHTML =
        '<span>No Such Machine</span>' +
        '<a href="/">Home</a>' +
        '<a href="https://bottle.nosuchmachine.net/">Daylight Bottle</a>' +
        '<a href="product-boundary.html">Product boundary</a>' +
        '<a href="https://github.com/chasebryan/-wuci-ji">Repository</a>';
      document.body.appendChild(footer);
    }
  }
  setupPageShell();

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
          if (document.contains(button)) {
            button.focus({ preventScroll: true });
          }
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

    function navItems() {
      return Array.prototype.slice.call(nav.querySelectorAll("a[href], button:not([disabled])"));
    }

    var desktopQuery = window.matchMedia("(min-width: 981px)");
    var suppressedRegions = [];
    var scrollLockState = null;
    var lastMenuFocus = null;

    function focusWithoutScroll(element) {
      if (!element || typeof element.focus !== "function") {
        return;
      }
      try {
        element.focus({ preventScroll: true });
      } catch (error) {
        element.focus();
      }
    }

    function suppressRegion(element) {
      if (!element || suppressedRegions.some(function (state) { return state.element === element; })) {
        return;
      }
      suppressedRegions.push({
        element: element,
        hadAriaHidden: element.hasAttribute("aria-hidden"),
        ariaHidden: element.getAttribute("aria-hidden"),
        hadInert: element.hasAttribute("inert"),
        inert: element.getAttribute("inert")
      });
      element.setAttribute("aria-hidden", "true");
      element.setAttribute("inert", "");
    }

    function suppressObscuredContent() {
      suppressedRegions = [];
      Array.prototype.forEach.call(document.body.children, function (element) {
        if (
          element === header ||
          element.tagName === "SCRIPT" ||
          element.tagName === "STYLE" ||
          element.tagName === "TEMPLATE"
        ) {
          return;
        }
        suppressRegion(element);
      });
      Array.prototype.forEach.call(header.children, function (element) {
        if (element !== nav && element !== toggle) {
          suppressRegion(element);
        }
      });
    }

    function restoreSuppressedContent() {
      suppressedRegions.forEach(function (state) {
        if (state.hadAriaHidden) {
          state.element.setAttribute("aria-hidden", state.ariaHidden || "");
        } else {
          state.element.removeAttribute("aria-hidden");
        }
        if (state.hadInert) {
          state.element.setAttribute("inert", state.inert || "");
        } else {
          state.element.removeAttribute("inert");
        }
      });
      suppressedRegions = [];
    }

    function freezePageScroll() {
      if (scrollLockState) {
        return;
      }
      var body = document.body;
      var scrollbarGap = Math.max(0, window.innerWidth - document.documentElement.clientWidth);
      scrollLockState = {
        x: window.scrollX,
        y: window.scrollY,
        hadStyle: body.hasAttribute("style"),
        style: body.getAttribute("style"),
        hadClass: body.classList.contains("nav-scroll-locked")
      };
      body.classList.add("nav-scroll-locked");
      body.style.position = "fixed";
      body.style.top = "-" + scrollLockState.y + "px";
      body.style.left = "-" + scrollLockState.x + "px";
      body.style.right = "0";
      body.style.width = "100%";
      body.style.overflow = "hidden";
      if (scrollbarGap > 0) {
        var currentPadding = parseFloat(window.getComputedStyle(body).paddingRight) || 0;
        body.style.paddingRight = currentPadding + scrollbarGap + "px";
      }
    }

    function restorePageScroll() {
      if (!scrollLockState) {
        return;
      }
      var state = scrollLockState;
      var body = document.body;
      var root = document.documentElement;
      scrollLockState = null;
      if (state.hadStyle) {
        body.setAttribute("style", state.style || "");
      } else {
        body.removeAttribute("style");
      }
      if (!state.hadClass) {
        body.classList.remove("nav-scroll-locked");
      }
      var previousScrollBehavior = root.style.scrollBehavior;
      root.style.scrollBehavior = "auto";
      window.scrollTo(state.x, state.y);
      root.style.scrollBehavior = previousScrollBehavior;
    }

    function setOpen(open, restoreToggleFocus) {
      var wasOpen = header.classList.contains("nav-open");
      if (open && desktopQuery.matches) {
        return;
      }
      if (open === wasOpen) {
        if (!open && restoreToggleFocus && !desktopQuery.matches) {
          focusWithoutScroll(toggle);
        }
        return;
      }
      if (open) {
        header.classList.add("nav-open");
        toggle.setAttribute("aria-expanded", "true");
        suppressObscuredContent();
        freezePageScroll();
        window.requestAnimationFrame(function () {
          var first = navItems()[0];
          if (first && header.classList.contains("nav-open")) {
            first.focus();
          }
        });
        return;
      }

      header.classList.remove("nav-open");
      toggle.setAttribute("aria-expanded", "false");
      restoreSuppressedContent();
      restorePageScroll();
      if (restoreToggleFocus && !desktopQuery.matches) {
        focusWithoutScroll(toggle);
      }
    }

    function samePageDestination(anchor) {
      var href = anchor.getAttribute("href");
      if (!href || href.indexOf("#") === -1) {
        return null;
      }
      var url;
      try {
        url = new URL(anchor.href, document.baseURI);
      } catch (error) {
        return null;
      }
      if (
        url.origin !== window.location.origin ||
        url.pathname !== window.location.pathname ||
        url.search !== window.location.search ||
        url.hash.length < 2
      ) {
        return null;
      }
      var id;
      try {
        id = decodeURIComponent(url.hash.slice(1));
      } catch (error) {
        return null;
      }
      var destination = document.getElementById(id);
      return destination ? { element: destination, hash: url.hash } : null;
    }

    function focusFragmentDestination(destination) {
      var element = destination.element;
      var hadTabIndex = element.hasAttribute("tabindex");
      if (!hadTabIndex) {
        element.setAttribute("tabindex", "-1");
        element.addEventListener("blur", function removeTemporaryTabIndex() {
          if (element.getAttribute("tabindex") === "-1") {
            element.removeAttribute("tabindex");
          }
        }, { once: true });
      }
      if (window.location.hash !== destination.hash) {
        try {
          window.history.pushState(null, "", destination.hash);
        } catch (error) {
          window.location.hash = destination.hash;
        }
      }
      focusWithoutScroll(element);
      var root = document.documentElement;
      var previousScrollBehavior = root.style.scrollBehavior;
      var headerOffset = Math.ceil(header.getBoundingClientRect().height) + 12;
      var targetTop = Math.max(0, element.getBoundingClientRect().top + window.scrollY - headerOffset);
      root.style.scrollBehavior = "auto";
      window.scrollTo(window.scrollX, targetTop);
      root.style.scrollBehavior = previousScrollBehavior;
    }

    toggle.addEventListener("click", function () {
      var wasOpen = header.classList.contains("nav-open");
      setOpen(!wasOpen, wasOpen);
    });

    nav.addEventListener("click", function (event) {
      var target = event.target;
      var anchor = target instanceof Element ? target.closest("a") : null;
      if (!anchor || event.defaultPrevented || event.button !== 0 || event.metaKey || event.ctrlKey || event.shiftKey || event.altKey) {
        return;
      }
      var destination = samePageDestination(anchor);
      if (destination) {
        event.preventDefault();
        setOpen(false, false);
        window.requestAnimationFrame(function () {
          focusFragmentDestination(destination);
        });
      } else {
        setOpen(false, false);
      }
    });

    header.addEventListener("focusin", function (event) {
      if (event.target === toggle || nav.contains(event.target)) {
        lastMenuFocus = event.target;
      }
    });

    document.addEventListener("keydown", function (event) {
      if (!header.classList.contains("nav-open")) {
        return;
      }
      if (event.key === "Escape") {
        event.preventDefault();
        setOpen(false, true);
        return;
      }
      if (event.key === "Tab") {
        var items = navItems();
        var first = items[0];
        var last = items[items.length - 1];
        var active = document.activeElement;
        if (!first) {
          event.preventDefault();
          toggle.focus();
          return;
        }
        if (active === toggle) {
          event.preventDefault();
          if (event.shiftKey) {
            last.focus();
          } else {
            first.focus();
          }
        } else if (event.shiftKey && active === first) {
          event.preventDefault();
          toggle.focus();
        } else if (!event.shiftKey && active === last) {
          event.preventDefault();
          toggle.focus();
        } else if (items.indexOf(active) === -1) {
          event.preventDefault();
          first.focus();
        }
      }
    });

    function visibleHeaderTarget(preferred) {
      var candidates = [];
      if (preferred) {
        candidates.push(preferred);
      }
      candidates = candidates.concat(navItems());
      candidates.push(header.querySelector(".brand"));
      for (var index = 0; index < candidates.length; index += 1) {
        var candidate = candidates[index];
        if (
          candidate &&
          candidate.getClientRects().length > 0 &&
          window.getComputedStyle(candidate).visibility !== "hidden"
        ) {
          return candidate;
        }
      }
      return null;
    }

    function handleChange(event) {
      if (event.matches) {
        var wasOpen = header.classList.contains("nav-open");
        var active = document.activeElement;
        var focusWasLostFromMenu =
          wasOpen &&
          active === document.body &&
          lastMenuFocus &&
          (lastMenuFocus === toggle || nav.contains(lastMenuFocus));
        if (wasOpen && (active === toggle || focusWasLostFromMenu)) {
          focusWithoutScroll(visibleHeaderTarget(lastMenuFocus === toggle ? null : lastMenuFocus));
        }
        setOpen(false, false);
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

  setupNavToggle();
  setupHeaderState();
  setupScrollSpy();
})();
