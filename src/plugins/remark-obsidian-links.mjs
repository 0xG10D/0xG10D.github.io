import path from 'node:path';

const imageExtensions = new Set(['.png', '.jpg', '.jpeg', '.gif', '.webp', '.svg']);
const wikilinkPattern = /(!)?\[\[([^\]]+?)\]\]/g;

function slugify(value) {
  return value
    .trim()
    .replace(/\\/g, '/')
    .replace(/\.[a-z0-9]+$/i, '')
    .split('/')
    .pop()
    .toLowerCase()
    .replace(/[^a-z0-9]+/g, '-')
    .replace(/^-+|-+$/g, '');
}

function encodePath(value) {
  return value
    .split('/')
    .map((segment) => encodeURIComponent(segment))
    .join('/');
}

function splitTarget(rawTarget) {
  const [target, alias] = rawTarget.split('|');
  return {
    target: target.trim(),
    label: (alias || target).trim()
  };
}

function nodesFromText(value, fileSlug) {
  const nodes = [];
  let lastIndex = 0;

  for (const match of value.matchAll(wikilinkPattern)) {
    const index = match.index ?? 0;
    if (index > lastIndex) {
      nodes.push({ type: 'text', value: value.slice(lastIndex, index) });
    }

    const isEmbed = Boolean(match[1]);
    const { target, label } = splitTarget(match[2]);
    const extension = path.extname(target).toLowerCase();

    if (isEmbed || imageExtensions.has(extension)) {
      nodes.push({
        type: 'image',
        url: `/images/writeups/${fileSlug}/${encodePath(target)}`,
        alt: label || path.basename(target)
      });
    } else {
      nodes.push({
        type: 'link',
        url: `/writeups/${slugify(target)}/`,
        title: null,
        children: [{ type: 'text', value: label }]
      });
    }

    lastIndex = index + match[0].length;
  }

  if (lastIndex < value.length) {
    nodes.push({ type: 'text', value: value.slice(lastIndex) });
  }

  return nodes;
}

function transformChildren(node, fileSlug) {
  if (!Array.isArray(node.children)) {
    return;
  }

  node.children = node.children.flatMap((child) => {
    if (child.type === 'text' && wikilinkPattern.test(child.value)) {
      wikilinkPattern.lastIndex = 0;
      return nodesFromText(child.value, fileSlug);
    }

    wikilinkPattern.lastIndex = 0;
    transformChildren(child, fileSlug);
    return child;
  });
}

export default function remarkObsidianLinks() {
  return function transformer(tree, file) {
    const filePath = file.history?.[0] || '';
    const fileSlug = slugify(path.basename(filePath));
    transformChildren(tree, fileSlug);
  };
}
