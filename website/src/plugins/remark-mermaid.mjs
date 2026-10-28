// Turn ```mermaid fences into <pre class="mermaid"> before Expressive Code sees them, so the
// diagram is drawn in the browser instead of shown as code. It can scroll, so it takes keyboard focus.
const escape = (s) => s.replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;');

export default function remarkMermaid() {
	const walk = (node) => {
		node.children?.forEach((child, i) => {
			if (child.type === 'code' && child.lang === 'mermaid') {
				node.children[i] = { type: 'html', value: `<pre class="mermaid" tabindex="0">${escape(child.value)}</pre>` };
			} else {
				walk(child);
			}
		});
	};
	return walk;
}
