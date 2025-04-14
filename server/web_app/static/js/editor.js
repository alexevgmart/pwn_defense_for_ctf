let editor;
let currentFile = null;

// Initialize editor
require(['vs/editor/editor.main'], function() {
    editor = monaco.editor.create(document.getElementById('editor'), {
        value: 'Select a JSON file to edit',
        language: 'json',
        theme: 'vs',
        automaticLayout: true,
        minimap: { enabled: true },
        scrollBeyondLastLine: false,
        formatOnPaste: true,
        formatOnType: true
    });

    // Update cursor position
    editor.onDidChangeCursorPosition(function(e) {
        document.getElementById('cursor-position').textContent = 
            `Line: ${e.position.lineNumber}, Column: ${e.position.column}`;
    });
    
    // Handle editor changes
    editor.onDidChangeModelContent(function() {
        document.getElementById('save-btn').disabled = !currentFile;
        validateJSON();
    });
});

// Validate JSON
function validateJSON() {
    try {
        JSON.parse(editor.getValue());
        document.getElementById('json-validity').textContent = 'valid';
        document.getElementById('json-validity').className = 'json-valid';
        return true;
    } catch (e) {
        document.getElementById('json-validity').textContent = 'invalid: ' + e.message;
        document.getElementById('json-validity').className = 'json-invalid';
        return false;
    }
}

// Render file list
function renderFileList(filter = '') {
    const fileList = document.getElementById('file-list');
    
    if (files.length === 0) {
        fileList.innerHTML = `
            <div class="empty-state">
                <i class="material-icons">folder_open</i>
                <p>No JSON files found</p>
            </div>
        `;
        return;
    }
    
    fileList.innerHTML = '';
    
    const filteredFiles = files.filter(file => 
        file.toLowerCase().includes(filter.toLowerCase())
    );
    
    if (filteredFiles.length === 0) {
        fileList.innerHTML = `
            <div class="empty-state">
                <i class="material-icons">search_off</i>
                <p>No matching files found</p>
            </div>
        `;
        return;
    }
    
    filteredFiles.forEach(file => {
        const btn = document.createElement('button');
        btn.className = `file-btn ${currentFile === file ? 'active' : ''}`;
        btn.innerHTML = `
            <i class="material-icons">code</i>
            <span>${file}</span>
        `;
        
        btn.addEventListener('click', () => loadFile(file));
        fileList.appendChild(btn);
    });
}

// Load file into editor
function loadFile(filename) {
    if (!filename.endsWith('.json')) {
        alert('Only JSON files can be edited');
        return;
    }
    
    currentFile = filename;
    document.getElementById('current-file').textContent = filename;
    document.getElementById('file-info').textContent = filename;
    
    // Update active file button
    document.querySelectorAll('.file-btn').forEach(btn => {
        btn.classList.remove('active');
        if (btn.querySelector('span').textContent === filename) {
            btn.classList.add('active');
        }
    });
    
    // Enable buttons that require a selected file
    document.getElementById('save-btn').disabled = true;
    document.getElementById('delete-btn').disabled = false;
    
    fetch(`/api/file?filename=${encodeURIComponent(filename)}`)
        .then(response => response.json())
        .then(data => {
            if (data.error) {
                alert(data.error);
                return;
            }
            
            const model = monaco.editor.createModel(
                data.content,
                'json'
            );
            
            editor.setModel(model);
            validateJSON();
        })
        .catch(error => {
            console.error('Error loading file:', error);
            alert('Failed to load file');
        });
}

// Save file
function saveFile() {
    if (!currentFile) return;
    
    if (!validateJSON()) {
        if (!confirm('JSON is invalid. Save anyway?')) {
            return;
        }
    }

    if (JSON.parse(editor.getValue())["service"] == "KERNEL" && JSON.parse(editor.getValue())["action"] != "ban") {
        alert("KERNEL patterns may only be banned (change 'action' to 'ban')");
        return;
    }

    if (JSON.parse(editor.getValue())["action"] != "mark" && JSON.parse(editor.getValue())["action"] != "ban") {
        alert("'action' may only be 'ban' or 'mark'");
        return;
    }

    if (JSON.parse(editor.getValue())["active"] != true && JSON.parse(editor.getValue())["active"] != false) {
        alert("'active' may only be true or false");
        return;
    }

    if (JSON.parse(editor.getValue())["std"] != null && JSON.parse(editor.getValue())["std"] !== 1 && JSON.parse(editor.getValue())["std"] !== 0) {
        alert("'std' may only be null, 0 or 1");
        return;
    }
    
    fetch('/api/file', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
            filename: currentFile,
            content: editor.getValue()
        })
    })
    .then(response => response.json())
    .then(data => {
        if (data.error) {
            alert('Error saving: ' + data.error);
        } else {
            document.getElementById('save-btn').disabled = true;
            alert('File saved successfully!');
        }
    })
    .catch(error => {
        console.error('Save error:', error);
        alert('Failed to save file');
    });
}

// Create new JSON file
function showNewFileModal() {
    document.getElementById('new-file-modal').style.display = 'flex';
    document.getElementById('new-filename').value = '';
    document.getElementById('new-filename').focus();
}

function createNewFile() {
    const filename = document.getElementById('new-filename').value.trim();
    if (!filename) {
        alert('Please enter a filename');
        return;
    }
    
    if (!filename.endsWith('.json')) {
        alert('Filename must end with .json');
        return;
    }
    
    fetch('/api/file/new', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
            filename: filename
        })
    })
    .then(response => response.json())
    .then(data => {
        if (data.error) {
            alert('Error: ' + data.error);
        } else {
            document.getElementById('new-file-modal').style.display = 'none';
            files.push(filename);
            renderFileList();
            loadFile(filename);
        }
    })
    .catch(error => {
        console.error('Create error:', error);
        alert('Failed to create file');
    });
}

// Delete file
function deleteFile() {
    if (!currentFile || !confirm(`Delete "${currentFile}"?`)) return;
    
    fetch('/api/file', {
        method: 'DELETE',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
            filename: currentFile
        })
    })
    .then(response => response.json())
    .then(data => {
        if (data.error) {
            alert('Error: ' + data.error);
        } else {
            const index = files.indexOf(currentFile);
            if (index !== -1) {
                files.splice(index, 1);
            }
            currentFile = null;
            editor.setValue('Select a JSON file to edit');
            document.getElementById('current-file').textContent = 'No file selected';
            document.getElementById('file-info').textContent = 'No file selected';
            document.getElementById('save-btn').disabled = true;
            document.getElementById('delete-btn').disabled = true;
            document.getElementById('json-validity').textContent = 'not checked';
            document.getElementById('json-validity').className = '';
            renderFileList();
        }
    })
    .catch(error => {
        console.error('Delete error:', error);
        alert('Failed to delete file');
    });
}

// Refresh file list
function refreshFileList() {
    fetch('/api/files')
        .then(response => response.json())
        .then(data => {
            if (data.error) {
                alert(data.error);
            } else {
                files.length = 0;
                files.push(...data.files);
                renderFileList();
            }
        })
        .catch(error => {
            console.error('Refresh error:', error);
            alert('Failed to refresh files');
        });
}

// Initialize on page load
document.addEventListener('DOMContentLoaded', function() {
    renderFileList();
    
    // Event listeners
    document.getElementById('save-btn').addEventListener('click', saveFile);
    document.getElementById('new-file-btn').addEventListener('click', showNewFileModal);
    document.getElementById('delete-btn').addEventListener('click', deleteFile);
    document.getElementById('refresh-btn').addEventListener('click', refreshFileList);
    document.getElementById('logout-btn').addEventListener('click', function() {
        fetch('/logout').then(() => window.location.href = '/login');
    });
    
    // Modal handlers
    document.getElementById('cancel-new-file').addEventListener('click', function() {
        document.getElementById('new-file-modal').style.display = 'none';
    });
    
    document.getElementById('confirm-new-file').addEventListener('click', createNewFile);
    
    // Close modal when clicking outside
    document.getElementById('new-file-modal').addEventListener('click', function(e) {
        if (e.target === this) {
            this.style.display = 'none';
        }
    });
    
    // File search
    document.getElementById('file-search').addEventListener('input', function(e) {
        renderFileList(e.target.value);
    });
    
    document.getElementById('search-btn').addEventListener('click', function() {
        renderFileList(document.getElementById('file-search').value);
    });
});