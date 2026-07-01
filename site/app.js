(function () {
  // Gallery lightbox
  function setupLightbox() {
    var figures = document.querySelectorAll("main figure");
    if (!figures.length) return;

    var lightbox = document.createElement("div");
    lightbox.className = "lightbox";
    lightbox.innerHTML = '<button class="lightbox-close" aria-label="Close">&times;</button><img src="" alt="">';
    document.body.appendChild(lightbox);

    var lightboxImg = lightbox.querySelector("img");
    var closeBtn = lightbox.querySelector(".lightbox-close");

    function openFigure(figure) {
      var img = figure.querySelector("img");
      if (img) {
        lightboxImg.src = img.src;
        lightboxImg.alt = img.alt;
        lightbox.classList.add("is-active");
        document.body.style.overflow = "hidden";
      }
    }

    figures.forEach(function (figure) {
      figure.setAttribute("role", "button");
      figure.setAttribute("tabindex", "0");
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
      document.body.style.overflow = "";
    }

    closeBtn.addEventListener("click", closeLightbox);
    lightbox.addEventListener("click", function (e) {
      if (e.target === lightbox) closeLightbox();
    });
    document.addEventListener("keydown", function (e) {
      if (e.key === "Escape" && lightbox.classList.contains("is-active")) {
        closeLightbox();
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

  var evidenceState = {
    finalScoreM: 998900,
    scorecardDigest: "4779e1a6c9f65266e2c291f8b66b8eeeb17d7f96e06d3b2d6de7db0bda8ad134",
    obligationsDigest: "c54c543d970a32cec982543fd8e3681b5d4501c3af7d0ceaf67d571a702dcf25",
    closedObligations: [
      "o.q1.doctrine_claim_bound",
      "o.q1.master_law_executable",
      "o.q10.implementation_tests",
      "o.q10.traceability_map",
      "o.q11.falsification_corpus_snapshot",
      "o.q11.falsification_harness",
      "o.q12.claim_communication",
      "o.q12.documentation_complete",
      "o.q2.exact_rational_proof",
      "o.q2.formal_density_tests",
      "o.q3.downgrade_machine",
      "o.q3.subtractive_corpus",
      "o.q4.fail_closed_tests",
      "o.q4.gate_harness_execution",
      "o.q5.evidence_sheaf_build",
      "o.q5.release_reproduction",
      "o.q6.boundary_matrix_tests",
      "o.q6.surface_adversarial_run",
      "o.q7.modeled_adversary_corpus",
      "o.q7.transcript_survival_corpus",
      "o.q8.classical_margin_source",
      "o.q8.kat_vector_tests",
      "o.q9.reproducibility_harness",
      "o.q9.statistical_outlier_corpus"
    ]
  };

  var envelopeProfile = "daylight-v15-meridian-browser-envelope-v1";
  var envelopeMagic = "WUCIMBE1";
  var textEncoder = new TextEncoder();
  var textDecoder = new TextDecoder();
  var downloadUrls = [];

  function query(selector) {
    return document.querySelector(selector);
  }

  function all(selector) {
    return Array.prototype.slice.call(document.querySelectorAll(selector));
  }

  function setStatus(element, message, kind) {
    if (!element) {
      return;
    }
    element.textContent = message;
    element.classList.remove("is-ok", "is-error");
    if (kind) {
      element.classList.add(kind);
    }
  }

  function canonicalize(value) {
    if (value === null) {
      return "null";
    }
    if (Array.isArray(value)) {
      return "[" + value.map(canonicalize).join(",") + "]";
    }
    if (typeof value === "object") {
      return "{" + Object.keys(value).sort().map(function (key) {
        return JSON.stringify(key) + ":" + canonicalize(value[key]);
      }).join(",") + "}";
    }
    if (typeof value === "string") {
      return JSON.stringify(value);
    }
    if (typeof value === "number") {
      if (!Number.isFinite(value)) {
        throw new Error("non-finite number cannot be canonicalized");
      }
      return String(value);
    }
    if (typeof value === "boolean") {
      return value ? "true" : "false";
    }
    throw new Error("unsupported canonical JSON value");
  }

  function concatBytes(parts) {
    var length = parts.reduce(function (sum, part) {
      return sum + part.length;
    }, 0);
    var output = new Uint8Array(length);
    var offset = 0;
    parts.forEach(function (part) {
      output.set(part, offset);
      offset += part.length;
    });
    return output;
  }

  async function sha256Bytes(input) {
    var data = typeof input === "string" ? textEncoder.encode(input) : input;
    return new Uint8Array(await crypto.subtle.digest("SHA-256", data));
  }

  async function sha256Hex(input) {
    var digest = await sha256Bytes(input);
    return Array.prototype.map.call(digest, function (byte) {
      return byte.toString(16).padStart(2, "0");
    }).join("");
  }

  function bytesToBase64url(bytes) {
    var binary = "";
    for (var offset = 0; offset < bytes.length; offset += 0x8000) {
      var chunk = bytes.subarray(offset, offset + 0x8000);
      binary += String.fromCharCode.apply(null, chunk);
    }
    return btoa(binary).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/g, "");
  }

  function base64urlToBytes(value) {
    var normalized = value.replace(/-/g, "+").replace(/_/g, "/");
    while (normalized.length % 4) {
      normalized += "=";
    }
    var binary = atob(normalized);
    var output = new Uint8Array(binary.length);
    for (var i = 0; i < binary.length; i += 1) {
      output[i] = binary.charCodeAt(i);
    }
    return output;
  }

  function parsePrivateKey(text) {
    var trimmed = text.trim();
    if (!trimmed) {
      throw new Error("private key is empty");
    }
    try {
      var keyObject = JSON.parse(trimmed);
      if (!keyObject || keyObject.key_format !== envelopeProfile || !keyObject.key_b64u) {
        throw new Error("key JSON is not a Meridian browser key");
      }
      return base64urlToBytes(keyObject.key_b64u);
    } catch (error) {
      if (/^[0-9a-fA-F]{64}$/.test(trimmed)) {
        var out = new Uint8Array(32);
        for (var i = 0; i < 32; i += 1) {
          out[i] = parseInt(trimmed.slice(i * 2, i * 2 + 2), 16);
        }
        return out;
      }
      if (/^[A-Za-z0-9_-]+$/.test(trimmed)) {
        return base64urlToBytes(trimmed);
      }
      throw error;
    }
  }

  function makeDownload(anchor, filename, bytes, type) {
    if (!anchor) {
      return;
    }
    var blob = new Blob([bytes], { type: type || "application/octet-stream" });
    var url = URL.createObjectURL(blob);
    downloadUrls.push(url);
    anchor.href = url;
    anchor.download = filename;
  }

  function clearDownloads() {
    downloadUrls.forEach(function (url) {
      URL.revokeObjectURL(url);
    });
    downloadUrls = [];
    all("[data-meridian-output], [data-meridian-open-output]").forEach(function (node) {
      node.hidden = true;
    });
  }

  function selectedRequiredObligations() {
    return all("[data-meridian-required]:checked").map(function (input) {
      return input.value;
    }).sort();
  }

  function makePolicy(minScoreM, requiredClosedObligations) {
    return {
      min_score_M: Number(minScoreM),
      required_closed_obligations: Array.from(new Set(requiredClosedObligations)).sort(),
      obligations_digest: evidenceState.obligationsDigest
    };
  }

  function policyRefusals(policy) {
    var reasons = [];
    var closed = new Set(evidenceState.closedObligations);
    if (!policy || typeof policy !== "object") {
      return ["policy is missing"];
    }
    if (!Number.isFinite(Number(policy.min_score_M))) {
      reasons.push("policy score floor is missing or invalid");
    }
    if (!Array.isArray(policy.required_closed_obligations)) {
      reasons.push("policy required-closed obligations are missing or invalid");
      policy.required_closed_obligations = [];
    }
    if (policy.obligations_digest !== evidenceState.obligationsDigest) {
      reasons.push("obligations digest does not match the published v15 registry");
    }
    if (policy.min_score_M > evidenceState.finalScoreM) {
      reasons.push("policy requires " + policy.min_score_M + "M, but the public site can prove only " + evidenceState.finalScoreM + "M");
    }
    policy.required_closed_obligations.forEach(function (obligation) {
      if (!closed.has(obligation)) {
        reasons.push("required obligation is not closed by this public evidence state: " + obligation);
      }
    });
    return reasons;
  }

  async function authorizationTag(policy) {
    var binding = {
      obligations_digest: evidenceState.obligationsDigest,
      scorecard_digest: evidenceState.scorecardDigest,
      final_score_M: evidenceState.finalScoreM,
      closed_obligation_ids: evidenceState.closedObligations.slice().sort(),
      policy: {
        min_score_M: policy.min_score_M,
        required_closed_obligations: policy.required_closed_obligations.slice().sort(),
        obligations_digest: policy.obligations_digest
      }
    };
    return sha256Hex("DAYLIGHT-v15-MERIDIAN-BROWSER-AUTH:" + canonicalize(binding));
  }

  async function deriveAesKey(rawKey, headerCanonical, authTag) {
    if (rawKey.length !== 32) {
      throw new Error("private key must be 32 bytes");
    }
    var baseKey = await crypto.subtle.importKey("raw", rawKey, "HKDF", false, ["deriveKey"]);
    var salt = await sha256Bytes(concatBytes([textEncoder.encode(envelopeMagic), textEncoder.encode(headerCanonical)]));
    return crypto.subtle.deriveKey(
      {
        name: "HKDF",
        hash: "SHA-256",
        salt: salt,
        info: textEncoder.encode("DAYLIGHT-v15-MERIDIAN-BROWSER-ENVELOPE v1 aead-key:" + authTag)
      },
      baseKey,
      { name: "AES-GCM", length: 256 },
      false,
      ["encrypt", "decrypt"]
    );
  }

  function setupTabs() {
    all("[data-tab-target]").forEach(function (button) {
      button.addEventListener("click", function () {
        var targetId = button.getAttribute("data-tab-target");
        all("[data-tab-target]").forEach(function (tab) {
          var active = tab === button;
          tab.classList.toggle("is-active", active);
          tab.setAttribute("aria-selected", active ? "true" : "false");
        });
        all(".tab-panel").forEach(function (panel) {
          var active = panel.id === targetId;
          panel.classList.toggle("is-active", active);
          panel.hidden = !active;
        });
      });
    });
  }

  async function encryptSelectedFile() {
    var fileInput = query("[data-meridian-file]");
    var minScore = query("[data-meridian-min-score]");
    var boundary = query("[data-meridian-boundary]");
    var status = query("[data-meridian-status]");
    var output = query("[data-meridian-output]");

    clearDownloads();
    try {
      if (!window.crypto || !crypto.subtle) {
        throw new Error("Web Crypto is not available in this browser context");
      }
      if (!fileInput || !fileInput.files || !fileInput.files[0]) {
        throw new Error("choose a file first");
      }
      if (!boundary || !boundary.checked) {
        throw new Error("confirm the research-boundary acknowledgement first");
      }

      var file = fileInput.files[0];
      var policy = makePolicy(Number(minScore.value), selectedRequiredObligations());
      var refusals = policyRefusals(policy);
      if (refusals.length) {
        throw new Error("Seal refused: " + refusals.join("; "));
      }

      var privateKey = crypto.getRandomValues(new Uint8Array(32));
      var nonce = crypto.getRandomValues(new Uint8Array(12));
      var authTag = await authorizationTag(policy);
      var header = {
        magic: envelopeMagic,
        version: envelopeProfile,
        suite: "AES-256-GCM-WebCrypto-HKDF-SHA256",
        nonce_b64u: bytesToBase64url(nonce),
        file: {
          name: file.name || "download.bin",
          type: file.type || "application/octet-stream",
          size: file.size,
          last_modified: file.lastModified || null
        },
        policy: policy,
        authorization: {
          obligations_digest: evidenceState.obligationsDigest,
          scorecard_digest: evidenceState.scorecardDigest,
          final_score_M: evidenceState.finalScoreM,
          closed_obligation_ids: evidenceState.closedObligations.slice().sort(),
          authorization_tag: authTag
        },
        boundary: "Browser-local research profile. Not production cryptography, not external certification, not byte-compatible with the Python ChaCha20-Poly1305 MAE reference."
      };
      var headerCanonical = canonicalize(header);
      var key = await deriveAesKey(privateKey, headerCanonical, authTag);
      var plaintext = new Uint8Array(await file.arrayBuffer());
      var aad = textEncoder.encode(envelopeMagic + "|" + headerCanonical);
      var ciphertext = new Uint8Array(await crypto.subtle.encrypt({ name: "AES-GCM", iv: nonce, additionalData: aad }, key, plaintext));
      var envelope = {
        envelope_format: envelopeProfile,
        created_at_utc: new Date().toISOString(),
        header: header,
        ciphertext_b64u: bytesToBase64url(ciphertext)
      };
      envelope.envelope_digest = await sha256Hex("DAYLIGHT-v15-MERIDIAN-BROWSER-ENVELOPE:" + canonicalize(envelope));

      var keyRecord = {
        key_format: envelopeProfile,
        created_at_utc: new Date().toISOString(),
        warning: "Private download key. Keep this separate from the encrypted envelope. The website cannot recover it.",
        envelope_digest: envelope.envelope_digest,
        key_b64u: bytesToBase64url(privateKey)
      };

      var safeName = (file.name || "file").replace(/[^\w.\-]+/g, "_");
      makeDownload(query("[data-meridian-envelope-download]"), safeName + ".mbe.json", JSON.stringify(envelope, null, 2), "application/json");
      makeDownload(query("[data-meridian-key-download]"), safeName + ".private-key.json", JSON.stringify(keyRecord, null, 2), "application/json");
      if (output) {
        output.hidden = false;
      }
      var copyButton = query("[data-meridian-copy-key]");
      if (copyButton) {
        copyButton.onclick = function () {
          if (!navigator.clipboard || !navigator.clipboard.writeText) {
            setStatus(status, "Clipboard is unavailable. Use the Download private key button.", "is-error");
            return;
          }
          navigator.clipboard.writeText(JSON.stringify(keyRecord, null, 2)).then(function () {
            copyButton.textContent = "Copied";
            window.setTimeout(function () {
              copyButton.textContent = "Copy key";
            }, 1600);
          });
        };
      }
      setStatus(status, "Seal permitted. Encrypted " + file.name + " locally under " + policy.min_score_M + "M policy. Download both the envelope and the private key.", "is-ok");
    } catch (error) {
      setStatus(status, error.message || String(error), "is-error");
    }
  }

  async function openSelectedEnvelope() {
    var fileInput = query("[data-meridian-open-file]");
    var keyInput = query("[data-meridian-open-key]");
    var boundary = query("[data-meridian-open-boundary]");
    var status = query("[data-meridian-open-status]");
    var output = query("[data-meridian-open-output]");

    clearDownloads();
    try {
      if (!window.crypto || !crypto.subtle) {
        throw new Error("Web Crypto is not available in this browser context");
      }
      if (!fileInput || !fileInput.files || !fileInput.files[0]) {
        throw new Error("choose an encrypted envelope first");
      }
      if (!keyInput || !keyInput.value.trim()) {
        throw new Error("paste the private download key");
      }
      if (!boundary || !boundary.checked) {
        throw new Error("confirm the local-open acknowledgement first");
      }

      var envelope = JSON.parse(await fileInput.files[0].text());
      if (!envelope || envelope.envelope_format !== envelopeProfile || !envelope.header) {
        throw new Error("not a Meridian browser envelope");
      }
      var header = envelope.header;
      if (header.magic !== envelopeMagic || header.version !== envelopeProfile) {
        throw new Error("unsupported envelope profile");
      }
      var refusals = policyRefusals(header.policy || {});
      if (refusals.length) {
        throw new Error("Open refused: " + refusals.join("; "));
      }
      var recomputedAuth = await authorizationTag(header.policy);
      if (!header.authorization || recomputedAuth !== header.authorization.authorization_tag) {
        throw new Error("Open refused: evidence does not reproduce the sealed authorization");
      }

      var privateKey = parsePrivateKey(keyInput.value);
      var headerCanonical = canonicalize(header);
      var key = await deriveAesKey(privateKey, headerCanonical, recomputedAuth);
      var nonce = base64urlToBytes(header.nonce_b64u);
      var aad = textEncoder.encode(envelopeMagic + "|" + headerCanonical);
      var ciphertext = base64urlToBytes(envelope.ciphertext_b64u);
      var plainBuffer = await crypto.subtle.decrypt({ name: "AES-GCM", iv: nonce, additionalData: aad }, key, ciphertext);
      var name = (header.file && header.file.name ? header.file.name : "opened.bin").replace(/[^\w.\-]+/g, "_");
      var type = header.file && header.file.type ? header.file.type : "application/octet-stream";
      makeDownload(query("[data-meridian-plain-download]"), name, new Uint8Array(plainBuffer), type);
      if (output) {
        output.hidden = false;
      }
      setStatus(status, "Open permitted. Policy and AEAD tag verified. Download the opened file.", "is-ok");
    } catch (error) {
      setStatus(status, error.message || String(error), "is-error");
    }
  }

  function setupMeridianWorkbench() {
    if (!query("[data-meridian-workbench]")) {
      return;
    }
    setupTabs();
    var encryptButton = query("[data-meridian-encrypt]");
    var openButton = query("[data-meridian-open]");
    var resetButton = query("[data-meridian-reset]");
    if (encryptButton) {
      encryptButton.addEventListener("click", encryptSelectedFile);
    }
    if (openButton) {
      openButton.addEventListener("click", openSelectedEnvelope);
    }
    if (resetButton) {
      resetButton.addEventListener("click", function () {
        clearDownloads();
        var fileInput = query("[data-meridian-file]");
        var boundary = query("[data-meridian-boundary]");
        if (fileInput) {
          fileInput.value = "";
        }
        if (boundary) {
          boundary.checked = false;
        }
        setStatus(query("[data-meridian-status]"), "Waiting for a file and an admissible policy.", "");
      });
    }
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
  setupMeridianWorkbench();
})();
