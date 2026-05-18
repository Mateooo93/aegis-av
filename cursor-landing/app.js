/* ==========================================
   CURSOR LANDING PAGE REPLICA JAVASCRIPT
   Logic: Live IDE simulations, spotlight grids, billing
   ========================================== */

document.addEventListener("DOMContentLoaded", () => {
  initMobileMenu();
  initBentoSpotlight();
  initHeroIDE();
  initFeaturesShowcase();
  initPricingToggle();
});

/* ==========================================
   1. Mobile Navigation Menu
   ========================================== */
function initMobileMenu() {
  const toggleBtn = document.querySelector(".mobile-menu-toggle");
  const mobileNav = document.querySelector(".mobile-nav");

  if (toggleBtn && mobileNav) {
    toggleBtn.addEventListener("click", () => {
      toggleBtn.classList.toggle("active");
      const isOpen = mobileNav.style.display === "flex";
      mobileNav.style.display = isOpen ? "none" : "flex";

      // Transform hamburger into cross
      const spans = toggleBtn.querySelectorAll("span");
      if (toggleBtn.classList.contains("active")) {
        spans[0].style.transform = "rotate(45deg) translate(5px, 5px)";
        spans[1].style.opacity = "0";
        spans[2].style.transform = "rotate(-45deg) translate(4px, -4px)";
      } else {
        spans[0].style.transform = "none";
        spans[1].style.opacity = "1";
        spans[2].style.transform = "none";
      }
    });

    // Close on link click
    mobileNav.querySelectorAll(".mobile-nav-link").forEach(link => {
      link.addEventListener("click", () => {
        mobileNav.style.display = "none";
        toggleBtn.classList.remove("active");
        toggleBtn.querySelectorAll("span").forEach(s => s.style.transform = "none");
        toggleBtn.querySelectorAll("span")[1].style.opacity = "1";
      });
    });
  }
}

/* ==========================================
   2. Bento Grid Mouse Spotlight Effect
   ========================================== */
function initBentoSpotlight() {
  const cards = document.querySelectorAll(".bento-card");
  
  cards.forEach(card => {
    card.addEventListener("mousemove", e => {
      const rect = card.getBoundingClientRect();
      const x = e.clientX - rect.left;
      const y = e.clientY - rect.top;

      // Update custom CSS variables for radial gradient center
      card.style.setProperty("--mouse-x", `${x}px`);
      card.style.setProperty("--mouse-y", `${y}px`);
    });
  });
}

/* ==========================================
   3. Hero IDE Simulation (The Centerpiece)
   ========================================== */

// Pre-defined code states with HTML markup for syntax highlighting
const heroCodeInitial = `
<div class="code-line"><span class="line-number">1</span><span class="code-content"><span class="token-comment">// Standard user record creation</span></span></div>
<div class="code-line"><span class="line-number">2</span><span class="code-content"><span class="token-keyword">function</span> <span class="token-function">saveUser</span>(<span class="token-param">user</span>) {</span></div>
<div class="code-line"><span class="line-number">3</span><span class="code-content">  <span class="token-keyword">const</span> <span class="token-param">query</span> <span class="token-operator">=</span> <span class="token-string">"INSERT INTO users VALUES (?, ?)"</span>;</span></div>
<div class="code-line"><span class="line-number">4</span><span class="code-content">  <span class="token-keyword">return</span> <span class="token-function">db.query</span>(query, [user.name, user.email]);</span></div>
<div class="code-line"><span class="line-number">5</span><span class="code-content">}</span></div>
`;

const heroCodeDiff = `
<div class="code-line"><span class="line-number">1</span><span class="code-content"><span class="token-comment">// Standard user record creation</span></span></div>
<div class="code-line line-removed"><span class="line-number">2</span><span class="code-content"><span class="token-keyword">function</span> <span class="token-function">saveUser</span>(<span class="token-param">user</span>) {</span></div>
<div class="code-line line-removed"><span class="line-number">3</span><span class="code-content">  <span class="token-keyword">const</span> <span class="token-param">query</span> <span class="token-operator">=</span> <span class="token-string">"INSERT INTO users VALUES (?, ?)"</span>;</span></div>
<div class="code-line line-removed"><span class="line-number">4</span><span class="code-content">  <span class="token-keyword">return</span> <span class="token-function">db.query</span>(query, [user.name, user.email]);</span></div>
<div class="code-line line-added"><span class="line-number">2</span><span class="code-content"><span class="token-keyword">async</span> <span class="token-keyword">function</span> <span class="token-function">saveUser</span>(<span class="token-param">user</span>) {</span></div>
<div class="code-line line-added"><span class="line-number">3</span><span class="code-content">  <span class="token-keyword">if</span> (<span class="token-operator">!</span>user.email.<span class="token-function">includes</span>(<span class="token-string">'@'</span>)) {</span></div>
<div class="code-line line-added"><span class="line-number">4</span><span class="code-content">    <span class="token-keyword">throw</span> <span class="token-keyword">new</span> <span class="token-classname">Error</span>(<span class="token-string">"Invalid email address"</span>);</span></div>
<div class="code-line line-added"><span class="line-number">5</span><span class="code-content">  }</span></div>
<div class="code-line line-added"><span class="line-number">6</span><span class="code-content">  <span class="token-keyword">const</span> <span class="token-param">hashedPass</span> <span class="token-operator">=</span> <span class="token-keyword">await</span> <span class="token-function">bcrypt.hash</span>(user.password, <span class="token-number">10</span>);</span></div>
<div class="code-line line-added"><span class="line-number">7</span><span class="code-content">  <span class="token-keyword">const</span> <span class="token-param">query</span> <span class="token-operator">=</span> <span class="token-string">"INSERT INTO users VALUES (?, ?, ?)"</span>;</span></div>
<div class="code-line line-added"><span class="line-number">8</span><span class="code-content">  <span class="token-keyword">return</span> <span class="token-function">db.query</span>(query, [user.name, user.email, hashedPass]);</span></div>
<div class="code-line"><span class="line-number">9</span><span class="code-content">}</span></div>
`;

const heroCodeFinal = `
<div class="code-line"><span class="line-number">1</span><span class="code-content"><span class="token-comment">// Standard user record creation</span></span></div>
<div class="code-line pulse-highlight"><span class="line-number">2</span><span class="code-content"><span class="token-keyword">async</span> <span class="token-keyword">function</span> <span class="token-function">saveUser</span>(<span class="token-param">user</span>) {</span></div>
<div class="code-line pulse-highlight"><span class="line-number">3</span><span class="code-content">  <span class="token-keyword">if</span> (<span class="token-operator">!</span>user.email.<span class="token-function">includes</span>(<span class="token-string">'@'</span>)) {</span></div>
<div class="code-line pulse-highlight"><span class="line-number">4</span><span class="code-content">    <span class="token-keyword">throw</span> <span class="token-keyword">new</span> <span class="token-classname">Error</span>(<span class="token-string">"Invalid email address"</span>);</span></div>
<div class="code-line pulse-highlight"><span class="line-number">5</span><span class="code-content">  }</span></div>
<div class="code-line pulse-highlight"><span class="line-number">6</span><span class="code-content">  <span class="token-keyword">const</span> <span class="token-param">hashedPass</span> <span class="token-operator">=</span> <span class="token-keyword">await</span> <span class="token-function">bcrypt.hash</span>(user.password, <span class="token-number">10</span>);</span></div>
<div class="code-line pulse-highlight"><span class="line-number">7</span><span class="code-content">  <span class="token-keyword">const</span> <span class="token-param">query</span> <span class="token-operator">=</span> <span class="token-string">"INSERT INTO users VALUES (?, ?, ?)"</span>;</span></div>
<div class="code-line pulse-highlight"><span class="line-number">8</span><span class="code-content">  <span class="token-keyword">return</span> <span class="token-function">db.query</span>(query, [user.name, user.email, hashedPass]);</span></div>
<div class="code-line"><span class="line-number">9</span><span class="code-content">}</span></div>
`;

const chatExplanation = `I see you are registering users by inserting plain attributes. I've refactored \`saveUser\` to:
1. **Validate inputs**: Raise an error if \`email\` lacks standard formatting.
2. **Hash passwords**: Securely process \`user.password\` with \`bcrypt\` asynchronously before saving.
3. **Handle Promises**: Refactored the method to be \`async\` to avoid blocking the event loop.`;

function initHeroIDE() {
  const editor = document.getElementById("editorContent");
  const ctrlK = document.getElementById("ctrlKBar");
  const ctrlKInput = document.getElementById("ctrlKInput");
  const ctrlKStatus = document.getElementById("ctrlKStatus");
  const chatResponse = document.getElementById("chatResponse");

  if (!editor || !ctrlK || !ctrlKInput || !chatResponse) return;

  const promptText = "make this async, validate email, and secure password with bcrypt";
  let activeState = 0; // State manager for the infinite loop

  // Typewriter Helper
  function typeText(targetElement, fullText, speed = 40, callback) {
    targetElement.value = "";
    let i = 0;
    
    function typing() {
      if (i < fullText.length) {
        targetElement.value += fullText.charAt(i);
        i++;
        setTimeout(typing, speed);
      } else if (callback) {
        callback();
      }
    }
    typing();
  }

  // HTML Typewriter Helper for Chat (rendering markdown-like content step-by-step)
  function typeHtml(targetElement, htmlText, speed = 10, callback) {
    targetElement.innerHTML = "";
    let i = 0;
    let tempText = "";

    function typing() {
      if (i < htmlText.length) {
        // Handle HTML tags directly so we don't break tags mid-rendering
        if (htmlText.charAt(i) === "<") {
          let tagEnd = htmlText.indexOf(">", i);
          tempText += htmlText.substring(i, tagEnd + 1);
          i = tagEnd + 1;
        } else {
          tempText += htmlText.charAt(i);
          i++;
        }
        targetElement.innerHTML = tempText + '<span class="cursor-blink"></span>';
        setTimeout(typing, speed);
      } else {
        // Remove blinker
        targetElement.innerHTML = tempText;
        if (callback) callback();
      }
    }
    typing();
  }

  // Main Loop Manager
  function runLoop() {
    // 1. Initial State: Load standard code block
    editor.innerHTML = heroCodeInitial;
    ctrlKInput.value = "";
    ctrlK.classList.remove("active");
    chatResponse.innerHTML = `<span class="token-comment">// Waiting for prompt...</span>`;

    // Wait 2.5s, then show Ctrl+K prompt bar
    setTimeout(() => {
      ctrlK.classList.add("active");
      ctrlKStatus.innerText = "Prompting...";
      
      // 2. Type out user AI edit instruction
      setTimeout(() => {
        typeText(ctrlKInput, promptText, 35, () => {
          ctrlKStatus.innerText = "Thinking...";
          ctrlKStatus.classList.add("pulse-highlight");

          // 3. Simulating thinking process, then reveal diff
          setTimeout(() => {
            ctrlKStatus.classList.remove("pulse-highlight");
            ctrlKStatus.innerText = "Applying edit...";
            editor.innerHTML = heroCodeDiff; // Load red/green diff

            // 4. Accept changes, load clean final state
            setTimeout(() => {
              ctrlK.classList.remove("active");
              editor.innerHTML = heroCodeFinal;

              // 5. Trigger right panel chat answer explanation typing
              setTimeout(() => {
                typeHtml(chatResponse, chatExplanation, 12, () => {
                  // Wait 10 seconds in final state, then restart
                  setTimeout(runLoop, 10000);
                });
              }, 1000);
            }, 3000);
          }, 1500);
        });
      }, 800);
    }, 2000);
  }

  // Start the cycle!
  runLoop();
}

/* ==========================================
   4. Features Tab Selector & Individual Simulations
   ========================================== */

// 4.1 Copilot++ Tab Code suggestion data
const tabDemoInitial = `
<div class="code-line"><span class="token-keyword">function</span> <span class="token-function">calculateTotal</span>(<span class="token-param">items, discount</span>) {</div>
<div class="code-line">  <span class="token-keyword">let</span> subtotal <span class="token-operator">=</span> items.<span class="token-function">reduce</span>((acc, item) <span class="token-operator">=></span> acc <span class="token-operator">+</span> item.price, <span class="token-number">0</span>);</div>
<div class="code-line" id="ghostLine">  <span class="cursor-blink"></span></div>
<div class="code-line">}</div>
`;

const tabDemoGhost = `
<div class="code-line"><span class="token-keyword">function</span> <span class="token-function">calculateTotal</span>(<span class="token-param">items, discount</span>) {</div>
<div class="code-line">  <span class="token-keyword">let</span> subtotal <span class="token-operator">=</span> items.<span class="token-function">reduce</span>((acc, item) <span class="token-operator">=></span> acc <span class="token-operator">+</span> item.price, <span class="token-number">0</span>);</div>
<div class="code-line" id="ghostLine"><span style="color: #6b7280; font-style: italic;">  const tax = subtotal * 0.08;</span></div>
<div class="code-line"><span style="color: #6b7280; font-style: italic;">  return (subtotal + tax) - discount;</span></div>
<div class="code-line">}</div>
`;

const tabDemoComplete = `
<div class="code-line"><span class="token-keyword">function</span> <span class="token-function">calculateTotal</span>(<span class="token-param">items, discount</span>) {</div>
<div class="code-line">  <span class="token-keyword">let</span> subtotal <span class="token-operator">=</span> items.<span class="token-function">reduce</span>((acc, item) <span class="token-operator">=></span> acc <span class="token-operator">+</span> item.price, <span class="token-number">0</span>);</div>
<div class="code-line line-added pulse-highlight"><span class="code-content">  <span class="token-keyword">const</span> tax <span class="token-operator">=</span> subtotal <span class="token-operator">*</span> <span class="token-number">0.08</span>;</span></div>
<div class="code-line line-added pulse-highlight"><span class="code-content">  <span class="token-keyword">return</span> (subtotal <span class="token-operator">+</span> tax) <span class="token-operator">-</span> discount;</span></div>
<div class="code-line">}</div>
`;

// 4.2 Composer Multiple File Edit Code data
const comp1Initial = `
<div class="code-line"><span class="token-keyword">const</span> mongoose <span class="token-operator">=</span> <span class="token-function">require</span>(<span class="token-string">'mongoose'</span>);</div>
<div class="code-line"><span class="token-keyword">const</span> UserSchema <span class="token-operator">=</span> <span class="token-keyword">new</span> <span class="token-classname">mongoose.Schema</span>({</div>
<div class="code-line">  name: <span class="token-classname">String</span>,</div>
<div class="code-line">  email: <span class="token-classname">String</span></div>
<div class="code-line">});</div>
`;

const comp1Complete = `
<div class="code-line"><span class="token-keyword">const</span> mongoose <span class="token-operator">=</span> <span class="token-function">require</span>(<span class="token-string">'mongoose'</span>);</div>
<div class="code-line"><span class="token-keyword">const</span> UserSchema <span class="token-operator">=</span> <span class="token-keyword">new</span> <span class="token-classname">mongoose.Schema</span>({</div>
<div class="code-line">  name: <span class="token-classname">String</span>,</div>
<div class="code-line">  email: <span class="token-classname">String</span>,</div>
<div class="code-line line-added pulse-highlight">  subscribed: <span class="token-classname">Boolean</span>,</div>
<div class="code-line line-added pulse-highlight">  subscriptionId: <span class="token-classname">String</span></div>
<div class="code-line">});</div>
`;

const comp2Initial = `
<div class="code-line"><span class="token-keyword">const</span> express <span class="token-operator">=</span> <span class="token-function">require</span>(<span class="token-string">'express'</span>);</div>
<div class="code-line"><span class="token-keyword">const</span> router <span class="token-operator">=</span> <span class="token-function">express.Router</span>();</div>
<div class="code-line"><span class="token-comment">// Handle basic events...</span></div>
`;

const comp2Complete = `
<div class="code-line"><span class="token-keyword">const</span> express <span class="token-operator">=</span> <span class="token-function">require</span>(<span class="token-string">'express'</span>);</div>
<div class="code-line"><span class="token-keyword">const</span> router <span class="token-operator">=</span> <span class="token-function">express.Router</span>();</div>
<div class="code-line line-added pulse-highlight"><span class="token-comment">// Handle stripe webhook events</span></div>
<div class="code-line line-added pulse-highlight">router.<span class="token-function">post</span>(<span class="token-string">'/webhook'</span>, <span class="token-keyword">async</span> (req, res) <span class="token-operator">=></span> {</div>
<div class="code-line line-added pulse-highlight">  <span class="token-keyword">const</span> user <span class="token-operator">=</span> <span class="token-keyword">await</span> User.<span class="token-function">findOne</span>({email: req.body.email});</div>
<div class="code-line line-added pulse-highlight">  user.subscribed <span class="token-operator">=</span> <span class="token-number">true</span>;</div>
<div class="code-line line-added pulse-highlight">  <span class="token-keyword">await</span> user.<span class="token-function">save</span>();</div>
<div class="code-line line-added pulse-highlight">  res.<span class="token-function">sendStatus</span>(<span class="token-number">200</span>);</div>
<div class="code-line line-added pulse-highlight">});</div>
`;

// 4.3 Codebase awareness simulator variables
const codebaseSearchQueries = [
  "How is user registration handled?",
  "Where are JWT tokens signed?",
  "Find all DB connection pools"
];

function initFeaturesShowcase() {
  const tabSelector = document.querySelectorAll(".selector-tab");
  const slides = document.querySelectorAll(".feature-slide");

  if (tabSelector.length === 0 || slides.length === 0) return;

  // Handle slide changing logic
  tabSelector.forEach(btn => {
    btn.addEventListener("click", () => {
      // 1. Remove actives
      tabSelector.forEach(b => b.classList.remove("active"));
      slides.forEach(s => s.classList.remove("active"));

      // 2. Add active to current
      btn.classList.add("active");
      const slideId = `slide-${btn.getAttribute("data-feature")}`;
      const targetSlide = document.getElementById(slideId);
      if (targetSlide) {
        targetSlide.classList.add("active");
        triggerSlideSimulation(btn.getAttribute("data-feature"));
      }
    });
  });

  // Run the default slide simulation
  triggerSlideSimulation("tab-autocomplete");
}

let activeIntervals = []; // Store timers so we can clear on tab swap

function triggerSlideSimulation(featureName) {
  // Clear previous intervals/timeouts
  activeIntervals.forEach(timer => clearTimeout(timer));
  activeIntervals = [];

  if (featureName === "tab-autocomplete") {
    runTabAutocompleteDemo();
  } else if (featureName === "composer") {
    runComposerDemo();
  } else if (featureName === "codebase-chat") {
    runCodebaseSearchDemo();
  }
}

// 4.1 Tab Autocomplete Demo Logic
function runTabAutocompleteDemo() {
  const container = document.getElementById("tabAutocompleteEditor");
  const btn = document.getElementById("btnTriggerTabDemo");
  const hint = document.getElementById("tabHint");

  if (!container || !btn || !hint) return;

  // Load initial clean code
  container.innerHTML = tabDemoInitial;
  btn.innerText = "Simulate Tab Autocomplete";
  btn.disabled = false;
  hint.innerText = "Waiting to type...";

  // 1. Simulate keypresses to trigger ghost suggestion
  const timer1 = setTimeout(() => {
    hint.innerText = "AI Suggestion ready! Click Trigger or Tab";
    container.innerHTML = tabDemoGhost;

    // Wait and click trigger or manual
    btn.onclick = () => {
      btn.disabled = true;
      btn.innerText = "Completed!";
      hint.innerText = "Applied via Copilot++";
      container.innerHTML = tabDemoComplete;
      
      // Flash glowing border effect
      const editorBox = container.closest(".mini-ide");
      editorBox.style.borderColor = "var(--accent-cyan)";
      editorBox.style.boxShadow = "0 0 20px rgba(0, 240, 255, 0.4)";
      
      const timerFlash = setTimeout(() => {
        editorBox.style.borderColor = "var(--border-color)";
        editorBox.style.boxShadow = "0 10px 30px rgba(0,0,0,0.4)";
      }, 1000);
      activeIntervals.push(timerFlash);
    };

  }, 2000);
  activeIntervals.push(timer1);

  // Set up autocomplete manual keyboard simulation on the button
  const triggerButton = document.getElementById("btnTriggerTabDemo");
  if (triggerButton) {
    triggerButton.style.display = "block";
  }
}

// 4.2 Composer Split Pane Demo Logic
function runComposerDemo() {
  const compOverlay = document.getElementById("composerBar");
  const file1 = document.getElementById("composerFile1");
  const file2 = document.getElementById("composerFile2");
  const btn = document.getElementById("btnTriggerComposerDemo");

  if (!compOverlay || !file1 || !file2 || !btn) return;

  // Reset
  file1.innerHTML = comp1Initial;
  file2.innerHTML = comp2Initial;
  btn.disabled = false;
  btn.innerText = "Trigger Multi-File Edit";
  compOverlay.style.borderColor = "var(--accent-purple)";
  compOverlay.style.boxShadow = "0 0 15px rgba(157, 78, 221, 0.2)";

  btn.onclick = () => {
    btn.disabled = true;
    btn.innerText = "Composer processing...";
    
    // Pulse overlay glow
    compOverlay.style.boxShadow = "0 0 25px rgba(157, 78, 221, 0.6)";

    // Modify file 1 after 1.5s
    const timerF1 = setTimeout(() => {
      file1.innerHTML = comp1Complete;
      const box1 = file1.closest(".mini-ide");
      box1.style.borderColor = "var(--accent-purple)";
      setTimeout(() => box1.style.borderColor = "var(--border-color)", 1000);
    }, 1200);
    activeIntervals.push(timerF1);

    // Modify file 2 after 2.8s
    const timerF2 = setTimeout(() => {
      file2.innerHTML = comp2Complete;
      const box2 = file2.closest(".mini-ide");
      box2.style.borderColor = "var(--accent-purple)";
      setTimeout(() => box2.style.borderColor = "var(--border-color)", 1000);
      
      btn.innerText = "Edits Completed!";
      compOverlay.style.boxShadow = "0 0 15px rgba(157, 78, 221, 0.2)";
    }, 2500);
    activeIntervals.push(timerF2);
  };
}

// 4.3 Codebase awareness simulator
function runCodebaseSearchDemo() {
  const searchInput = document.getElementById("codebaseSearchInput");
  const progressLog = document.getElementById("searchProgressLog");
  const resultsList = document.getElementById("searchResultsList");
  const btn = document.getElementById("btnTriggerSearchDemo");

  if (!searchInput || !progressLog || !resultsList || !btn) return;

  // Reset
  searchInput.value = "";
  progressLog.innerHTML = "";
  resultsList.innerHTML = "";
  btn.disabled = false;
  btn.innerText = "Simulate Repository Query";

  // Typewriter standard query search
  function typeQueryText(txt, cb) {
    let index = 0;
    function typing() {
      if (index < txt.length) {
        searchInput.value += txt.charAt(index);
        index++;
        setTimeout(typing, 40);
      } else {
        cb();
      }
    }
    typing();
  }

  btn.onclick = () => {
    btn.disabled = true;
    btn.innerText = "Searching codebase...";
    searchInput.value = "";

    // Type query
    typeQueryText(codebaseSearchQueries[0], () => {
      // 1. Show progress logs
      const logs = [
        "🔍 Parsing index for query structures...",
        "⚡ Scanning active file hashes...",
        "📂 Index match completed! Parsing blocks..."
      ];

      progressLog.innerHTML = `<div class="progress-log-item">${logs[0]}</div>`;

      const tLog1 = setTimeout(() => {
        progressLog.innerHTML += `<div class="progress-log-item">${logs[1]}</div>`;
      }, 1000);
      activeIntervals.push(tLog1);

      const tLog2 = setTimeout(() => {
        progressLog.innerHTML += `<div class="progress-log-item done">✔️ ${logs[2]}</div>`;
        
        // 2. Print results cards
        resultsList.innerHTML = `
          <div class="search-result-card pulse-highlight">
            <div class="result-file-header">
              <span>src/controllers/auth.js:L42</span>
              <span class="result-relevance">98% Match</span>
            </div>
            <div class="result-snippet">function handleRegister(req, res) { saveUser(req.body); ... }</div>
          </div>
          <div class="search-result-card pulse-highlight" style="animation-delay: 0.2s;">
            <div class="result-file-header">
              <span>src/auth.js:L1</span>
              <span class="result-relevance">82% Match</span>
            </div>
            <div class="result-snippet">function saveUser(user) { const query = ... }</div>
          </div>
        `;

        btn.innerText = "Done!";
      }, 2000);
      activeIntervals.push(tLog2);

    });
  };
}

/* ==========================================
   5. Pricing Billing Switcher (Monthly/Yearly)
   ========================================== */
function initPricingToggle() {
  const toggleBtn = document.getElementById("billingToggle");
  const monthlyLabel = document.getElementById("toggleMonthly");
  const yearlyLabel = document.getElementById("toggleYearly");
  
  const proPrice = document.getElementById("proPrice");
  const bizPrice = document.getElementById("bizPrice");

  if (!toggleBtn || !monthlyLabel || !yearlyLabel || !proPrice || !bizPrice) return;

  function setBilling(frequency) {
    if (frequency === "yearly") {
      toggleBtn.classList.add("active");
      yearlyLabel.classList.add("active");
      monthlyLabel.classList.remove("active");

      // Animate price update
      updatePriceWithAnimation(proPrice, proPrice.getAttribute("data-yearly"));
      updatePriceWithAnimation(bizPrice, bizPrice.getAttribute("data-yearly"));
    } else {
      toggleBtn.classList.remove("active");
      monthlyLabel.classList.add("active");
      yearlyLabel.classList.remove("active");

      updatePriceWithAnimation(proPrice, proPrice.getAttribute("data-monthly"));
      updatePriceWithAnimation(bizPrice, bizPrice.getAttribute("data-monthly"));
    }
  }

  function updatePriceWithAnimation(element, targetPrice) {
    // Add pop-in animation
    element.style.transform = "scale(0.9)";
    element.style.opacity = "0.5";
    
    setTimeout(() => {
      element.innerText = targetPrice;
      element.style.transform = "scale(1)";
      element.style.opacity = "1";
    }, 150);
  }

  // Click toggle button
  toggleBtn.addEventListener("click", () => {
    const isYearly = toggleBtn.classList.contains("active");
    setBilling(isYearly ? "monthly" : "yearly");
  });

  // Click labels
  monthlyLabel.addEventListener("click", () => setBilling("monthly"));
  yearlyLabel.addEventListener("click", () => setBilling("yearly"));
}
