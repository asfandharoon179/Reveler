// Core Logic for Image Steganography

// LSB Encoding Helper
function mergeTextInImageData(imgData, text) {
    const encoder = new TextEncoder();
    const textBytes = encoder.encode(text);
    
    const payload = new Uint8Array(4 + textBytes.length);
    const len = textBytes.length;
    payload[0] = (len >> 24) & 0xFF;
    payload[1] = (len >> 16) & 0xFF;
    payload[2] = (len >> 8) & 0xFF;
    payload[3] = len & 0xFF;
    payload.set(textBytes, 4);

    if (payload.length * 8 > imgData.data.length) {
        alert("Image is too small to hide this amount of text.");
        return null;
    }

    let dataIdx = 0;
    for (let i = 0; i < payload.length; i++) {
        for (let bit = 7; bit >= 0; bit--) {
            const b = (payload[i] >> bit) & 1;
            imgData.data[dataIdx] = (imgData.data[dataIdx] & 0xFE) | b;
            dataIdx++;
            if ((dataIdx + 1) % 4 === 0) dataIdx++; 
        }
    }
    return imgData;
}

// LSB Decoding Helper
function extractTextFromImageData(imgData) {
    let dataIdx = 0;
    
    function readByte() {
        let byteVal = 0;
        for (let bit = 7; bit >= 0; bit--) {
            if (dataIdx >= imgData.data.length) return null;
            const b = imgData.data[dataIdx] & 1;
            byteVal = (byteVal << 1) | b;
            dataIdx++;
            if ((dataIdx + 1) % 4 === 0) dataIdx++; 
        }
        return byteVal;
    }

    let len = 0;
    for (let i = 0; i < 4; i++) {
        const b = readByte();
        if (b === null) return null;
        len = (len << 8) | b;
    }

    if (len <= 0 || len > imgData.data.length) return null;

    const textBytes = new Uint8Array(len);
    for (let i = 0; i < len; i++) {
        const b = readByte();
        if (b === null) return null;
        textBytes[i] = b;
    }

    try {
        const decoder = new TextDecoder();
        return decoder.decode(textBytes);
    } catch(e) {
        return null;
    }
}

function setupDragAndDrop(dropZone, fileInput, onFileSelected) {
    dropZone.addEventListener('click', () => fileInput.click());
    
    // Prevent default drag behaviors
    ['dragenter', 'dragover', 'dragleave', 'drop'].forEach(eventName => {
        document.body.addEventListener(eventName, preventDefaults, false);
    });

    function preventDefaults(e) {
        e.preventDefault();
        e.stopPropagation();
    }

    // Highlight drop zone when item is dragged over it
    ['dragenter', 'dragover'].forEach(eventName => {
        dropZone.addEventListener(eventName, highlight, false);
    });

    ['dragleave', 'drop'].forEach(eventName => {
        dropZone.addEventListener(eventName, unhighlight, false);
    });

    function highlight(e) {
        dropZone.style.transform = 'scale(1.02)';
        dropZone.style.background = 'var(--primary-hover)';
    }

    function unhighlight(e) {
        dropZone.style.transform = '';
        dropZone.style.background = '';
    }

    dropZone.addEventListener('drop', (e) => {
        const dt = e.dataTransfer;
        const files = dt.files;
        if (files.length > 0) {
            onFileSelected(files[0]);
        }
    });

    fileInput.addEventListener('change', (e) => {
        if (e.target.files.length > 0) {
            onFileSelected(e.target.files[0]);
        }
    });
}

// Setup for Hide Tool
function initHideTool() {
    const dropZone = document.getElementById('dropZone');
    const fileInput = document.getElementById('fileInput');
    const origPreview = document.getElementById('origPreview');
    const previewArea = document.getElementById('previewArea');
    const downloadArea = document.getElementById('downloadArea');
    const fileNameDisplay = document.getElementById('fileNameDisplay');
    const sidebarOptions = document.getElementById('sidebarOptions');
    const textContent = document.getElementById('textContent');
    const passwordInput = document.getElementById('password');
    const btnEncrypt = document.getElementById('btnEncrypt');
    const btnDownload = document.getElementById('btnDownload');
    
    let originalImageElement = null;
    let processedBlobUrl = null;
    let currentFileName = "";

    setupDragAndDrop(dropZone, fileInput, (file) => {
        if(!file.type.match('image.*')) {
            alert("Please select an image file.");
            return;
        }
        currentFileName = file.name;
        const reader = new FileReader();
        reader.onload = function(event) {
            const img = new Image();
            img.onload = function() {
                originalImageElement = img;
                origPreview.src = event.target.result;
                fileNameDisplay.textContent = file.name;
                
                dropZone.style.display = 'none';
                previewArea.style.display = 'flex';
                sidebarOptions.classList.add('active');
            };
            img.src = event.target.result;
        };
        reader.readAsDataURL(file);
    });

    btnEncrypt.addEventListener('click', () => {
        if (!originalImageElement) return;
        
        let text = textContent.value;
        if (!text) {
            alert("Please enter text content to hide.");
            return;
        }

        const password = passwordInput.value;
        if (password) {
            text = "ENC:" + CryptoJS.AES.encrypt(text, password).toString();
        }

        const canvas = document.getElementById('processCanvas');
        canvas.width = originalImageElement.width;
        canvas.height = originalImageElement.height;
        const ctx = canvas.getContext('2d');
        ctx.drawImage(originalImageElement, 0, 0);

        let imgData = ctx.getImageData(0, 0, canvas.width, canvas.height);
        imgData = mergeTextInImageData(imgData, text);

        if (imgData) {
            ctx.putImageData(imgData, 0, 0);
            const formatInput = document.querySelector('input[name="downloadFormat"]:checked');
            const format = formatInput ? formatInput.value : 'image/png';
            
            canvas.toBlob((blob) => {
                if(processedBlobUrl) URL.revokeObjectURL(processedBlobUrl);
                processedBlobUrl = URL.createObjectURL(blob);
                
                previewArea.style.display = 'none';
                downloadArea.style.display = 'block';
                sidebarOptions.classList.remove('active');
            }, format);
        }
    });

    btnDownload.addEventListener('click', () => {
        if (!processedBlobUrl) return;
        const formatInput = document.querySelector('input[name="downloadFormat"]:checked');
        const format = formatInput ? formatInput.value : 'image/png';
        const ext = format === 'image/png' ? 'png' : 'jpg';
        const baseName = currentFileName.split('.').slice(0, -1).join('.') || 'image';
        
        const link = document.createElement('a');
        link.href = processedBlobUrl;
        link.download = `${baseName}_hidden.${ext}`;
        link.click();
    });
}

// Setup for Extract Tool
function initExtractTool() {
    const dropZone = document.getElementById('dropZone');
    const fileInput = document.getElementById('fileInput');
    const origPreview = document.getElementById('origPreview');
    const previewArea = document.getElementById('previewArea');
    const resultArea = document.getElementById('resultArea');
    const fileNameDisplay = document.getElementById('fileNameDisplay');
    const sidebarOptions = document.getElementById('sidebarOptions');
    const textContent = document.getElementById('textContent');
    const passwordInput = document.getElementById('password');
    const btnDecrypt = document.getElementById('btnDecrypt');
    const btnCopy = document.getElementById('btnCopy');
    
    let originalImageElement = null;

    setupDragAndDrop(dropZone, fileInput, (file) => {
        if(!file.type.match('image.*')) {
            alert("Please select an image file.");
            return;
        }
        const reader = new FileReader();
        reader.onload = function(event) {
            const img = new Image();
            img.onload = function() {
                originalImageElement = img;
                origPreview.src = event.target.result;
                fileNameDisplay.textContent = file.name;
                
                dropZone.style.display = 'none';
                previewArea.style.display = 'flex';
                sidebarOptions.classList.add('active');
            };
            img.src = event.target.result;
        };
        reader.readAsDataURL(file);
    });

    btnDecrypt.addEventListener('click', () => {
        if (!originalImageElement) return;

        const canvas = document.getElementById('processCanvas');
        canvas.width = originalImageElement.width;
        canvas.height = originalImageElement.height;
        const ctx = canvas.getContext('2d');
        ctx.drawImage(originalImageElement, 0, 0);

        const imgData = ctx.getImageData(0, 0, canvas.width, canvas.height);
        let extractedText = extractTextFromImageData(imgData);

        if (!extractedText) {
            alert("No hidden data found or format unsupported.");
            return;
        }

        if (extractedText.startsWith("ENC:")) {
            const password = passwordInput.value;
            if (!password) {
                alert("This data is password-protected. Please provide the correct password.");
                return;
            }
            try {
                const encryptedPayload = extractedText.substring(4);
                const bytes = CryptoJS.AES.decrypt(encryptedPayload, password);
                const decryptedText = bytes.toString(CryptoJS.enc.Utf8);
                if (!decryptedText) throw new Error();
                textContent.value = decryptedText;
            } catch (e) {
                alert("Failed to decrypt text. Wrong password?");
                return;
            }
        } else {
            textContent.value = extractedText;
        }

        previewArea.style.display = 'none';
        resultArea.style.display = 'block';
        sidebarOptions.classList.remove('active');
    });

    btnCopy.addEventListener('click', () => {
        textContent.select();
        document.execCommand('copy');
        
        const originalText = btnCopy.textContent;
        btnCopy.textContent = "Copied!";
        setTimeout(() => {
            btnCopy.textContent = originalText;
        }, 2000);
    });
}
