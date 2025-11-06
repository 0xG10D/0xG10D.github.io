// Theme toggle stored in localStorage
const themeToggle = document.getElementById('theme-toggle');
const root = document.documentElement;

// default dark
function setLight(val){
  if(val) {
    root.style.setProperty('--bg','#f7f7fa');
    root.style.setProperty('--panel','#ffffff');
    root.style.setProperty('--card','#ffffff');
    root.style.setProperty('--text','#0b0b0b');
    localStorage.setItem('site-theme','light');
  } else {
    root.style.removeProperty('--bg');
    root.style.removeProperty('--panel');
    root.style.removeProperty('--card');
    root.style.removeProperty('--text');
    localStorage.setItem('site-theme','dark');
  }
}

// load saved state
const saved = localStorage.getItem('site-theme');
if(saved === 'light') {
  themeToggle.checked = true;
  setLight(true);
} else {
  themeToggle && (themeToggle.checked = false);
  setLight(false);
}

// toggler
themeToggle && themeToggle.addEventListener('change', (e)=>{
  setLight(e.target.checked);
});

// search (two inputs map to same posts)
const posts = Array.from(document.querySelectorAll('.post-card'));
function runSearch(q){
  q = q.trim().toLowerCase();
  posts.forEach(p=>{
    const text = (p.textContent || '').toLowerCase();
    p.style.display = (!q || text.indexOf(q) !== -1) ? '' : 'none';
  });
}
const s1 = document.getElementById('search-input');
const s2 = document.getElementById('search-input-2');
[s1,s2].forEach(inp=>{
  if(!inp) return;
  inp.addEventListener('input', ()=> runSearch(inp.value));
});
