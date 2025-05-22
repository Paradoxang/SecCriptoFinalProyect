document.getElementById('fileInput').addEventListener('change', function(event) {
    const file = event.target.files[0];
    if (!file) {
        return;
    }

    const reader = new FileReader();

    reader.onload = function(e) {
        const arrayBuffer = e.target.result;
        const byteArray = new Uint8Array(arrayBuffer);
        const hexString = Array.from(byteArray)
            .map(byte => byte.toString(16).padStart(2, '0'))
            .join(' ');
        document.getElementById('output').textContent = hexString;
    };

    reader.readAsArrayBuffer(file);
});
