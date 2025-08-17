function initFaceCapture(verify) {
    const video = document.getElementById('video');
    const canvas = document.getElementById('canvas');
    const captureBtn = document.getElementById('capture_btn');
    const statusDiv = document.getElementById('status');
    const socket = io();

    navigator.mediaDevices.getUserMedia({ video: true })
        .then(function(stream) {
            video.srcObject = stream;
        })
        .catch(function(err) {
            statusDiv.innerText = "Camera access denied!";
        });

    captureBtn.onclick = function() {
        canvas.getContext('2d').drawImage(video, 0, 0, canvas.width, canvas.height);
        canvas.toBlob(function(blob) {
            blob.arrayBuffer().then(buffer => {
                if (verify) {
                    socket.emit('verify_face', { img: buffer });
                } else {
                    socket.emit('face_image', { img: buffer });
                }
            });
        }, 'image/jpeg');
    };

    socket.on('face_status', function(data) {
        statusDiv.innerText = data.msg;
        if (data.success) {
            setTimeout(function() {
                window.location.href = verify ? '/face_verified' : '/login';
            }, 500);
        }
    });
}