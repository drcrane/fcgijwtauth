"use strict";
function fileEditorInitalise() {
	const editorTextarea = document.getElementById('editorTextarea');

	if (!editorTextarea) {
		return;
	}

	const saveButton = document.getElementById('saveButton');
	const cancelButton = document.getElementById('cancelButton');
	const statusDot = document.getElementById('statusDot');
	const statusText = document.getElementById('statusText');
	
	let initialText = editorTextarea ? editorTextarea.value : ""; // Store initial text for comparison
	let isModified = false;
	
	// Function to format the current time
	function formatCurrentTime() {
		const now = new Date();
		const options = {
			year: 'numeric',
			month: 'numeric',
			day: 'numeric',
			hour: '2-digit',
			minute: '2-digit',
			second: '2-digit'
		};
		return now.toLocaleDateString('en-GB', options); // Using en-GB for DD/MM/YYYY hh:mm:ss format
	}
	
	if (saveButton && cancelButton) {
		saveButton.addEventListener('click', () => {
			initialText = editorTextarea.value;
			isModified = false;
		
			const currentTime = formatCurrentTime();
			localStorage.setItem('lastSavedTime', currentTime);
			statusText.textContent = `Last saved: ${currentTime}`;
			statusDot.classList.remove('modified');
			statusDot.classList.add('saved');
			//alert('Content saved!'); // For demonstration
		});
		
		// Resets text to the last saved state
		cancelButton.addEventListener('click', () => {
			editorTextarea.value = initialText; // Revert to the initial (last saved) text
			updateStatus();
			//alert('Changes cancelled!'); // For demonstration
		});
	}
	
	// Event listener for textarea input
	if (editorTextarea) {
		// Function to update the status indicator
		function updateStatus() {
			if (editorTextarea.value !== initialText) {
				if (!isModified) {
					isModified = true;
					statusDot.classList.add('modified');
					statusDot.classList.remove('saved');
					statusText.textContent = "Unsaved changes";
				}
			} else {
				if (isModified) {
					isModified = false;
					statusDot.classList.remove('modified');
					statusDot.classList.add('saved');
					// If text is back to initial, show last saved time or "Never"
					const lastSavedTime = localStorage.getItem('lastSavedTime');
					statusText.textContent = `Last saved: ${lastSavedTime || 'Never'}`;
				}
			}
		}
	
		editorTextarea.addEventListener('input', updateStatus);
	}
	
	// Initialize text on page load to allow cancel to work...
	document.addEventListener('DOMContentLoaded', () => {
		/*
		 * TODO: alter server-side to provide last modified time in a form
		 * field maybe?
		 */
		/*
		const lastSavedTime = localStorage.getItem('lastSavedTime');
		if (lastSavedTime) {
			statusText.textContent = `Last saved: ${lastSavedTime}`;
		} else {
			statusText.textContent = `Last saved: Never`;
		}
		*/
		// the editorTextarea value will be initialised by the server when
		// the HTML is rendered, we can save this here.
		initialText = editorTextarea.value;
		updateStatus();
	});
	
	const fileStatusMessage = document.getElementById('fileStatusMessage');
	
	let fileWillBeCreated = (() => {
		const params = new URLSearchParams(window.location.search);
		const value = params.get('createfile');
		if (value === 'true') {
			return true;
		} else {
			return false;
		}
	})();
	
	function updateFileStatusMessage() {
		if (fileWillBeCreated) {
			fileStatusMessage.style.display = 'inline';
		} else {
			fileStatusMessage.style.display = 'none';
		}
	}
	
	document.addEventListener('DOMContentLoaded', () => {
		updateFileStatusMessage();
	});
}

fileEditorInitalise();

