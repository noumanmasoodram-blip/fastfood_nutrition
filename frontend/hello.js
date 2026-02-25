// === UI ELEMENT SELECTORS ===
const countrySelect = document.getElementById("countrySelect");
const branchSection = document.getElementById("branchSection");
const branchContainer = document.getElementById("branchContainer");
const searchSection = document.getElementById("searchSection");
const searchInput = document.getElementById("searchInput");
const resultsDiv = document.getElementById("results");
const randomBtn = document.getElementById("randomBtn");
const clearFilters = document.getElementById("clearFilters");
const selectedBranch = document.getElementById("selectedBranch");
const selectedCountry = document.getElementById("selectedCountry");
const mobileMenuBtn = document.getElementById("mobileMenuBtn");
const mobileNav = document.getElementById("mobileNav");
const closeMobileMenu = document.getElementById("closeMobileMenu");
const backToTop = document.getElementById("backToTop");

let currentCountryId = null;
let currentBranchId = null;
let foodItems = [];

// Logo mapping for known brands (Assuming these images are available in the root of your Netlify deployment)
const brandLogos = {
 "burger king": "/burgerking1.png",
 "dominos": "/domino1.png",
 "domino's": "/domino2.png",
 "dunkin": "/dunkin1.png",
 "dunkin'": "/dunkin2.png",
 "mcdonald": "/mcdonalds1.png",
 "mcdonald's": "/mcdonalds2.png",
 "pizza hut": "/pizzahut1.png",
 "starbucks": "/starbucks1.png",
 "taco bell": "/tacobell1.png",
 "wendys": "/wendys1.png",
 "wendy's": "/wendys2.png",
 "kfc": "/kfc1.png",
 "kentucky fried chicken": "/kfc2.png", 
 "subway": "/subway1.png"
};

// Initialize countries on page load
async function fetchCountries() {
 try {
  // 🔑 FIX: Removed backendUrl variable, using relative path /api/countries
  const res = await fetch(`/api/countries`);
  if (!res.ok) throw new Error("Failed to fetch countries");
  const countries = await res.json();

  countrySelect.innerHTML = '<option value="">Select Country</option>';
  countries.forEach(country => {
   const option = document.createElement("option");
   option.value = country.id;
   option.textContent = country.name;
   countrySelect.appendChild(option);
  });
 } catch (err) {
  console.error("Error fetching countries:", err);
  // Display error message to user
  countrySelect.innerHTML = '<option value="">Failed to load countries</option>';
 }
}

async function fetchBranches(countryId) {
 try {
  branchContainer.innerHTML = '<div class="col-span-full text-center py-8"><div class="loading-spinner mx-auto mb-3 border-blue-500"></div><p class="text-gray-500">Loading branches...</p></div>';
  
  // 🔑 FIX: Removed backendUrl variable, using relative path /api/branches
  const res = await fetch(`/api/branches?country_id=${countryId}`);
  if (!res.ok) throw new Error("Failed to fetch branches");
  const branches = await res.json();

  branchContainer.innerHTML = '';
  
  if (branches.length === 0) {
   branchContainer.innerHTML = '<div class="col-span-full text-center py-4 text-gray-500"><i class="fas fa-store-slash text-2xl mb-2"></i><p>No branches available for this country</p></div>';
   return;
  }

  branches.forEach(branch => {
   // ... (rest of your branch item creation logic remains the same)
   const branchItem = document.createElement("div");
   branchItem.className = "branch-item";
   branchItem.dataset.branchId = branch.id;
   branchItem.dataset.branchName = branch.name;
   
   // Find the appropriate logo
   const branchNameLower = branch.name.toLowerCase();
   let logoUrl = "data:image/svg+xml;base64,PHN2ZyB4bWxucz0iaHR0cDovL3d3dy53My5vcmcvMjAwMC9zdmciIHZpZXdCb3g9IjAgMCAyNDAgMjQwIiBmaWxsPSIjMDAwIj48dGV4dCB4PSI4MCIgeT0iMTMwIiBmb250LWZhbWlseT0iQXJpYWwiIGZvbnQtc2l6ZT0iMTIiPkJyYW5jaDwvdGV4dD48L3N2Zz4=";
   
   // Check for exact matches first
   if (brandLogos[branchNameLower]) {
    logoUrl = brandLogos[branchNameLower];
   } else {
    // Check for partial matches
    for (const [key, url] of Object.entries(brandLogos)) {
     if (branchNameLower.includes(key)) {
      logoUrl = url;
      break;
     }
    }
   }
   
   branchItem.innerHTML = `
    <img src="${logoUrl}" 
      alt="${branch.name}" 
      class="branch-logo rounded-lg object-contain"
      onerror="this.src='data:image/svg+xml;base64,PHN2ZyB4bWxucz0iaHR0cDovL3d3dy53My5vcmcvMjAwMC9zdmciIHZpZXdCb3g9IjAgMCAyNDAgMjQwIiBmaWxsPSIjMDAwIj48dGV4dCB4PSI4MCIgeT0iMTMwIiBmb250LWZhbWlseT0iQXJpYWwiIGZvbnQtc2l6ZT0iMTIiPkJyYW5jaDwvdGV4dD48L3N2Zz4='">
    <span class="branch-name">${branch.name}</span>
   `;
   
   branchItem.addEventListener("click", () => {
    // Remove active class from all items
    document.querySelectorAll(".branch-item").forEach(item => {
     item.classList.remove("active");
     item.querySelector(".branch-logo").classList.remove("active");
    });
    
    // Add active class to clicked item
    branchItem.classList.add("active");
    branchItem.querySelector(".branch-logo").classList.add("active");
    
    currentBranchId = branch.id;
    selectedBranch.textContent = branch.name;
    
    // Show search section
    searchSection.classList.remove("hidden");
    
    // Scroll to search section on mobile
    if (window.innerWidth < 768) {
     searchSection.scrollIntoView({ behavior: 'smooth', block: 'start' });
    }
    
    // Fetch menu items
    fetchItems(currentCountryId, currentBranchId);
   });
   
   branchContainer.appendChild(branchItem);
  });
 } catch (err) {
  console.error("Error fetching branches:", err);
  branchContainer.innerHTML = '<div class="col-span-full text-center py-4 text-gray-500"><i class="fas fa-exclamation-triangle text-2xl mb-2"></i><p>Failed to load branches</p></div>';
 }
}

async function fetchItems(countryId, branchId) {
 try {
  resultsDiv.innerHTML = `
   <div class="col-span-full text-center py-8">
    <div class="loading-spinner mx-auto mb-3 border-blue-500"></div>
    <p class="text-gray-600">Loading menu items...</p>
   </div>
  `;
  
  // 🔑 FIX: Removed backendUrl variable, using relative path /api/items
  const res = await fetch(`/api/items?country_id=${countryId}&branch_id=${branchId}`);
  if (!res.ok) throw new Error("Failed to fetch items");
  foodItems = await res.json();
  
  displayResults(foodItems);
 } catch (err) {
  console.error("Error fetching items:", err);
  resultsDiv.innerHTML = `
   <div class="col-span-full text-center py-8">
    <i class="fas fa-exclamation-triangle text-4xl text-gray-400 mb-3"></i>
    <h3 class="text-base font-medium text-gray-700 mb-1">Failed to load menu items</h3>
    <p class="text-gray-500 text-sm">Please try again later</p>
   </div>
  `;
 }
}

function displayResults(items) {
 resultsDiv.innerHTML = "";
 if (items.length === 0) {
  resultsDiv.innerHTML = `
   <div class="col-span-full text-center py-8">
    <i class="fas fa-search text-4xl text-gray-400 mb-3"></i>
    <h3 class="text-base font-medium text-gray-700 mb-1">No menu items found</h3>
    <p class="text-gray-500 text-sm">Try adjusting your search term</p>
   </div>
  `;
  return;
 }

 // ✅ Food categories and icons (rest of this logic is unchanged)
 const foodCategories = {
  // ... (rest of your foodCategories object)
  pizza: {
   icon: `<i class="fas fa-pizza-slice"></i>`,
   keywords: ['pizza', 'margherita', 'pepperoni', 'supreme', 'hawaiian', 'cheese', 'meat lovers', 'veggie lovers']
  },
  chicken: {
   icon: `<i class="fas fa-drumstick-bite"></i>`,
   keywords: ['chicken', 'wing', 'nugget', 'tender', 'fillet', 'popcorn', 'fried chicken', 'grilled chicken']
  },
  fries: {
   icon: `<i class="fas fa-bowl-food"></i>`,
   keywords: [
    'fries', 'french fries', 'potato', 'chips', 'crispy fries', 'potato wedges', 'curly fries', 
    'waffle fries', 'seasoned fries', 'crinkle fries', 'sweet potato fries', 'loaded fries',
    'cheese fries', 'bacon fries', 'golden fries', 'potato twisters', 'potato sticks',
    'hash brown', 'hashbrowns', 'fries box', 'fries meal', 'potato chips', 'potato fries',
    'thick cut fries', 'steak fries'
   ]
  },
  mashed_potatoes: {
   icon: `<i class="fas fa-utensil-spoon"></i>`,
   keywords: [
    'mashed potato', 'mashed potatoes', 'potato mash', 'mashed potatoes with gravy',
    'mashed potato bowl', 'potato bowl', 'potato puree', 'pureed potato'
   ]
  },
  baked_potatoes: {
   icon: `<i class="fas fa-utensils"></i>`,
   keywords: ['baked potato', 'baked potatoes', 'potato skins', 'stuffed potato']
  },
  burger: {
   icon: `<i class="fas fa-hamburger"></i>`,
   keywords: ['burger', 'whopper', 'cheeseburger', 'hamburger', 'big mac']
  },
  sandwich: {
   icon: `<i class="fas fa-bread-slice"></i>`,
   keywords: ['sandwich', 'wrap', 'sub', 'panini', 'club']
  },
  pasta: {
   icon: `<i class="fas fa-bowl-rice"></i>`,
   keywords: ['pasta', 'macaroni', 'spaghetti', 'mac & cheese', 'lasagna']
  },
  coffee: {
   icon: `<i class="fas fa-coffee"></i>`,
   keywords: ['coffee', 'latte', 'cappuccino', 'espresso', 'frappuccino']
  },
  drink: {
   icon: `<i class="fas fa-glass-whiskey"></i>`,
   keywords: ['drink', 'juice', 'tea', 'lemonade', 'soda', 'water', 'smoothie', 'shake']
  },
  dessert: {
   icon: `<i class="fas fa-ice-cream"></i>`,
   keywords: ['ice cream', 'cake', 'cookie', 'pie', 'brownie', 'donut', 'muffin']
  },
  sauce: {
   icon: `<i class="fas fa-fill-drip"></i>`,
   keywords: ['sauce', 'dip', 'dressing', 'ketchup', 'mayo', 'mustard', 'ranch', 'gravy']
  }
 };

 // ✅ Fallback icons for random/unique foods
 const randomIcons = [
  `<i class="fas fa-bowl-food"></i>`,
  `<i class="fas fa-burger"></i>`,
  `<i class="fas fa-ice-cream"></i>`,
  `<i class="fas fa-apple-alt"></i>`,
  `<i class="fas fa-carrot"></i>`,
  `<i class="fas fa-fish"></i>`,
  `<i class="fas fa-cookie-bite"></i>`,
  `<i class="fas fa-hotdog"></i>`,
  `<i class="fas fa-egg"></i>`,
  `<i class="fas fa-pepper-hot"></i>`,
  `<i class="fas fa-bread-slice"></i>`
 ];

 function detectFoodCategory(itemName) {
  const name = itemName.toLowerCase();
  const priorityOrder = [
   'fries', 'mashed_potatoes', 'baked_potatoes', 'pizza', 'burger', 'chicken',
   'sandwich', 'pasta', 'coffee', 'drink', 'dessert', 'sauce'
  ];

  for (const category of priorityOrder) {
   const categoryData = foodCategories[category];
   if (categoryData) {
    for (const keyword of categoryData.keywords) {
     if (name.includes(keyword)) return category;
    }
   }
  }
  return null; // no match found
 }

 items.forEach((item, index) => {
  if (!item.id) return;

  // ✅ USE THE ORIGINAL CSS GRADIENT CLASSES (food-category-1 to food-category-5)
  const categoryClass = `food-category-${(index % 5) + 1}`;
  
  // Detect food category or assign random icon if unique
  const category = detectFoodCategory(item.name);
  let icon;

  if (category) {
   icon = foodCategories[category].icon;
  } else {
   // Random icon for unknown/unique items
   icon = randomIcons[Math.floor(Math.random() * randomIcons.length)];
  }

  const card = document.createElement("div");
  // ✅ USING ORIGINAL CSS GRADIENT CLASSES - NO WHITE BACKGROUND
  card.className = `food-card ${categoryClass} rounded-xl p-4 h-full flex flex-col transition-all duration-300 hover:shadow-lg`;

  card.innerHTML = `
   <div class="food-content flex-1 flex flex-col">
    <div class="food-icon">
     ${icon}
    </div>
    <h3 class="text-lg font-bold text-gray-800 mb-2">${item.name}</h3>
    <p class="text-gray-700 text-sm mb-3 flex-1">${item.serving_size || 'Standard serving'}</p>
    <div class="flex items-center justify-between mt-auto">
     <span class="text-xs font-medium text-gray-700">View nutrition details</span>
     <i class="fas fa-chevron-right text-gray-700 text-sm"></i>
    </div>
   </div>
  `;

  card.addEventListener("click", () => {
   const countryName = encodeURIComponent(selectedCountry.textContent.toLowerCase().replace(/\s+/g, '-'));
   const branchName = encodeURIComponent(selectedBranch.textContent.toLowerCase().replace(/\s+/g, '-'));
   window.location.href = `/item.html?country=${countryName}&branch=${branchName}&id=${encodeURIComponent(item.id)}`;
  });

  resultsDiv.appendChild(card);
 });
}
// Event Listeners
randomBtn.addEventListener("click", () => {
 if (foodItems.length > 0) {
  const randomItem = foodItems[Math.floor(Math.random() * foodItems.length)];
  // Since 'item.html' is a local file, it's correct to use a relative path here.
  window.location.href = `/item.html?id=${encodeURIComponent(randomItem.id)}`; 
 } else {
  // NOTE: Changed alert() to console.log as alerts are discouraged in the environment.
  console.log("Please select a country and branch first.");
 }
});

clearFilters.addEventListener("click", () => {
 searchInput.value = "";
 if (foodItems.length > 0) {
  displayResults(foodItems);
 }
});

countrySelect.addEventListener("change", () => {
 currentCountryId = countrySelect.value;
 const countryName = countrySelect.options[countrySelect.selectedIndex].text;
 
 if (currentCountryId) {
  branchSection.classList.remove("hidden");
  selectedCountry.textContent = countryName;
  fetchBranches(currentCountryId);
  
  // Scroll to branches on mobile
  if (window.innerWidth < 768) {
   branchSection.scrollIntoView({ behavior: 'smooth', block: 'start' });
  }
 } else {
  branchSection.classList.add("hidden");
  searchSection.classList.add("hidden");
  // Clear results when country is deselected
  resultsDiv.innerHTML = '';
 }
});

searchInput.addEventListener("input", () => {
 const searchTerm = searchInput.value.toLowerCase();
 const filtered = foodItems.filter(item =>
  item.name.toLowerCase().includes(searchTerm)
 );
 displayResults(filtered);
});

// Mobile menu functionality (Unchanged)
mobileMenuBtn.addEventListener("click", () => {
 mobileNav.classList.add("open");
 document.body.style.overflow = 'hidden';
});

closeMobileMenu.addEventListener("click", () => {
 mobileNav.classList.remove("open");
 document.body.style.overflow = 'auto';
});

document.querySelectorAll('#mobileNav a').forEach(link => {
 link.addEventListener('click', () => {
  mobileNav.classList.remove("open");
  document.body.style.overflow = 'auto';
 });
});

// Back to top functionality (Unchanged)
window.addEventListener("scroll", () => {
 if (window.pageYOffset > 300) {
  backToTop.classList.add("visible");
 } else {
  backToTop.classList.remove("visible");
 }
});

backToTop.addEventListener("click", () => {
 window.scrollTo({ top: 0, behavior: "smooth" });
});

// Smooth scrolling for anchor links (Unchanged)
document.querySelectorAll('a[href^="#"]').forEach(anchor => {
 anchor.addEventListener('click', function (e) {
  e.preventDefault();
  const target = document.querySelector(this.getAttribute('href'));
  if (target) {
   target.scrollIntoView({
    behavior: 'smooth',
    block: 'start'
   });
  }
 });
});

// Initialize countries on page load
fetchCountries();