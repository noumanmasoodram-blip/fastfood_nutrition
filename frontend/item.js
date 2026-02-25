
// --- Helper Functions ---
function getQueryParam(param) {
const urlParams = new URLSearchParams(window.location.search);
const val = urlParams.get(param);
return val && val.trim() !== "" && val !== "undefined" ? val : null;
}

function formatNutritionValue(value) {
 if (value === null || value === undefined || value === "N/A") return "N/A";
 const num = parseFloat(value);
 return isNaN(num) ? String(value) : num.toFixed(1);
}

// --- Fetch and Display Item Details ---
async function fetchFoodDetailsById(id) {
 // 🔑 FIX: Using relative path /api/item. Netlify handles the proxy to Heroku.
 const res = await fetch(`/api/item?id=${encodeURIComponent(id)}`);
 if (!res.ok) throw new Error(`API Error: ${res.status}`);
 return res.json();
}

async function fetchFoodDetailsByName(name) {
 // 🔑 FIX: Using relative path /api/item. Netlify handles the proxy to Heroku.
 const res = await fetch(`/api/item?name=${encodeURIComponent(name)}`);
 if (!res.ok) throw new Error(`API Error: ${res.status}`);
 return res.json();
}

function displayItem(item) {
 document.getElementById("itemName").textContent = item.name || "N/A";
 document.getElementById("serving_size").textContent = item.serving_size || "N/A";
 document.getElementById("calories").textContent = item.calories || "N/A";
 document.getElementById("total_fat").textContent = formatNutritionValue(item.total_fat);
 document.getElementById("saturated_fat").textContent = formatNutritionValue(item.saturated_fat);
 document.getElementById("trans_fat").textContent = formatNutritionValue(item.trans_fat);
 document.getElementById("cholesterol").textContent = item.cholesterol || "N/A";
 document.getElementById("sodium").textContent = item.sodium || "N/A";
 document.getElementById("carbohydrates").textContent = formatNutritionValue(item.carbohydrates);
 document.getElementById("sugars").textContent = formatNutritionValue(item.sugars);
 document.getElementById("protein").textContent = formatNutritionValue(item.protein);

 const nutritionDetailsEl = document.getElementById("nutritionDetails");
 if (nutritionDetailsEl) nutritionDetailsEl.classList.remove("opacity-0");
}

function showError(message, icon = "exclamation-circle", color = "red") {
 const itemNameEl = document.getElementById("itemName");
 if (itemNameEl) itemNameEl.textContent = message;

 const nutritionDetailsEl = document.getElementById("nutritionDetails");
 if (nutritionDetailsEl) {
  nutritionDetailsEl.innerHTML = `
   <div class="text-center p-8">
    <i class="fas fa-${icon} text-6xl text-${color}-500 mb-4"></i>
    <h2 class="text-xl font-semibold text-gray-800">${message}</h2>
    <p class="text-gray-600">Please check the URL or try again later.</p>
   </div>
  `;
 }
}

// --- Page Init ---
document.addEventListener("DOMContentLoaded", async () => {
 const backBtn = document.getElementById("backBtn");
 if (backBtn) backBtn.addEventListener("click", () => window.history.back());

 const itemId = getQueryParam("id");
 const itemName = getQueryParam("item");

 try {
  let item;

  if (itemName) {
   document.getElementById("itemName").textContent = "Loading...";
   item = await fetchFoodDetailsByName(itemName);
  } else if (itemId) {
   document.getElementById("itemName").textContent = "Loading...";
   item = await fetchFoodDetailsById(itemId);
  } else {
   showError("Invalid Item", "barcode", "yellow");
   return;
  }

  if (!item || Object.keys(item).length === 0) {
   showError("Item Not Found", "utensils", "orange");
   return;
  }

  displayItem(item);
 } catch (err) {
  console.error("Error fetching food details:", err);
  showError("Error Loading Item", "exclamation-circle", "red");
 }
  
 // Existing URL parameter logic for Branch and Country text
 const urlParams = new URLSearchParams(window.location.search);
 const branch = urlParams.get('branch');
 const country = urlParams.get('country');
 
 if (branch) {
  document.getElementById('branchText').textContent = branch;
 }
 
 if (country) {
  document.getElementById('countryText').textContent = country;
 }
});

// --- Mobile Menu Functionality (Unchanged) ---
document.addEventListener('DOMContentLoaded', function() {
      const mobileMenuBtn = document.getElementById('mobileMenuBtn');
      const closeMobileMenu = document.getElementById('closeMobileMenu');
      const mobileNav = document.getElementById('mobileNav');
      
      if (mobileMenuBtn && mobileNav && closeMobileMenu) {
        mobileMenuBtn.addEventListener('click', function() {
          mobileNav.classList.add('open');
          document.body.style.overflow = 'hidden';
        });
        
        closeMobileMenu.addEventListener('click', function() {
          mobileNav.classList.remove('open');
          document.body.style.overflow = 'auto';
        });
        
        // Close mobile menu when clicking on links
        document.querySelectorAll('#mobileNav a').forEach(link => {
          link.addEventListener('click', function() {
            mobileNav.classList.remove('open');
            document.body.style.overflow = 'auto';
          });
        });
      }
    });
// --- Mobile UX Enhancements ---
document.addEventListener("touchstart", () => {}, { passive: true });