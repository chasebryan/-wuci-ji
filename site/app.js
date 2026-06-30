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

      if (navigator.clipboard && navigator.clipboard.writeText) {
        navigator.clipboard.writeText(value).then(showCopied, function () {
          button.textContent = "Copy failed";
        });
        return;
      }

      var textArea = document.createElement("textarea");
      textArea.value = value;
      textArea.setAttribute("readonly", "readonly");
      textArea.style.position = "fixed";
      textArea.style.opacity = "0";
      document.body.appendChild(textArea);
      textArea.select();

      try {
        document.execCommand("copy");
        showCopied();
      } catch (error) {
        button.textContent = "Copy failed";
      } finally {
        document.body.removeChild(textArea);
      }
    });
  });
})();
