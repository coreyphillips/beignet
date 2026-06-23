import { expect } from 'chai';
import * as fs from 'fs';
import * as path from 'path';

describe('AI Agent Deployment Guide', () => {
	const guidePath = path.join(__dirname, '../../docs/AI_AGENT_GUIDE.md');
	const readmePath = path.join(__dirname, '../../README.md');

	it('guide file exists', () => {
		expect(fs.existsSync(guidePath)).to.be.true;
	});

	it('README links to the guide', () => {
		const readme = fs.readFileSync(readmePath, 'utf8');
		expect(readme).to.include('AI_AGENT_GUIDE.md');
	});
});
