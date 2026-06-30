(function () {
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
})();
