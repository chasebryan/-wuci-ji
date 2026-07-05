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

  setupNavToggle();
  setupHeaderState();
  setupScrollSpy();
})();
