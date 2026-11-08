document.addEventListener('DOMContentLoaded', () => {
  const input = document.getElementById('imageInput');
  const preview = document.getElementById('previewImage');

  if (!input || !preview) {
    return;
  }

  input.addEventListener('change', (event) => {
    const file = event.target.files[0];

    if (!file) {
      return;
    }

    const reader = new FileReader();
    reader.onload = (readerEvent) => {
      preview.src = readerEvent.target.result;
      preview.classList.remove('placeholder');
    };
    reader.readAsDataURL(file);
  });
});
