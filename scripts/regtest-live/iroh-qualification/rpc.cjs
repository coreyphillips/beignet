'use strict';
fetch('http://127.0.0.1:8089', { method: 'POST', body: process.argv[2] })
	.then((r) => r.text())
	.then((text) => process.stdout.write(text))
	.catch((error) => {
		console.error(error.message);
		process.exit(1);
	});
