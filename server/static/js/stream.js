function getIdFromPath() {
    const pathSegments = window.location.pathname.split('/');
    const id = pathSegments[pathSegments.length - 1];
    return id;
}

// const encodedData = "{{ data }}";

// const decodedData = JSON.parse(atob(encodedData));

const container = document.getElementById('stream-data');
let isBytesMode = false;

function textToHex(text) {
    const byteArray = new TextEncoder().encode(text);
    const hexArray = Array.from(byteArray).map(byte => byte.toString(16).padStart(2, '0'));
    const hexString = hexArray.join(' ');

    return hexString.replace(/0a/g, '0a<br>');
}

function replaceNonPrintableChars(text) {
    let result = '';
    for (let i = 0; i < text.length; i++) {
        const char = text[i];
        const charCode = char.charCodeAt(0);

        if (charCode >= 32 && charCode <= 126) {
            result += char;
        } else {
            result += `\\x${charCode.toString(16).padStart(2, '0')}`;
        }
    }
    return result;
}

function renderData() {
    container.innerHTML = ''; // Очищаем контейнер
    let counter = 1; // Счетчик для нумерации сообщений

    decodedData.forEach(item => {
        const type = item[0] ? 'output' : 'input';
        let content = atob(item[2]);

        if (isBytesMode) {
            content = textToHex(content);
        } else {
            content = content.replace(/\n/g, '<br>');
            content = replaceNonPrintableChars(content);
        }

        const div = document.createElement('div');
        div.className = type;
        div.innerHTML = `<strong>[${counter}] ${type}:</strong><br>${content}<br><br>`;
        container.appendChild(div);

        counter++; // Увеличиваем счетчик после каждого сообщения
    });
}

renderData();

const toggleButton = document.getElementById('toggle-bytes');
toggleButton.addEventListener('click', () => {
    isBytesMode = !isBytesMode;
    toggleButton.textContent = isBytesMode ? "Показать в ascii" : "Показать в байтах (hex)";
    renderData();
});

const exportButton = document.getElementById('export-sploit');
exportButton.addEventListener('click', async () => {
    const id = getIdFromPath();
    if (!id) {
        alert("ID не найден в URL.");
        return;
    }

    try {
        const response = await fetch(`/export_sploit/${id}`, {
            method: 'GET',
        });

        if (!response.ok) {
            throw new Error(`Ошибка: ${response.status}`);
        }

        const blob = await response.blob();

        const url = window.URL.createObjectURL(blob);
        const a = document.createElement('a');
        a.href = url;
        a.download = `splo_${id}.py`;
        document.body.appendChild(a);
        a.click();
        document.body.removeChild(a);
        window.URL.revokeObjectURL(url);
    } catch (error) {
        console.error("Ошибка при экспорте:", error);
        alert("Не удалось экспортировать данные.");
    }
});