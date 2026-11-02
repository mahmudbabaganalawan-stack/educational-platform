// Select the hamburger button
const menuToggle = document.getElementById("menu-toggle");

// Select the navigation links
const navLinks = document.querySelector(".nav-links");

// Open and close the menu
menuToggle.addEventListener("click", function () {

    navLinks.classList.toggle("active");

    const isOpen = navLinks.classList.contains("active");

    menuToggle.setAttribute("aria-expanded", isOpen);

    menuToggle.setAttribute(
        "aria-label",
        isOpen ? "Close navigation menu" : "Open navigation menu"
    );

    menuToggle.textContent = isOpen ? "✕" : "☰";

});
