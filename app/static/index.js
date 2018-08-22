/*global jQuery */
(function ($) {
    "use strict";

    jQuery(document).ready(function ($) {
        /*---------------------------------
         All Window Scroll Function Start
        --------------------------------- */
        $(window).on('scroll', function () {
            // Scroll up Hide Show
            if ($(window).scrollTop() >= 500) {
                $('.scroll-top').fadeIn(600);
            } else {
                $('.scroll-top').fadeOut(600);
            }

            //  Header Fixed JS
            if ($(window).scrollTop() > 200) {
                $('.header-bottom').addClass('fixedmenu');
            } else {
                $('.header-bottom').removeClass('fixedmenu');
            }
        });
        /*--------------------------------
         All Window Scroll Function End
        --------------------------------- */
        // Click to Scroll TOP
        $(".scroll-top").on('click', function () {
            $('html, body').animate({
                scrollTop: 0
            }, 1500);
        }); //Scroll TOP End

        // Home One Slider JS
        $("#slider-area").owlCarousel({
            items: 1,
            loop: true,
            dots: true,
            autoplay: true
        });

        // Video Popup JS
        $('.v-popup').magnificPopup({
            type: 'iframe'
        });

        // DropDown Menu JS
        $(".mainmenu li").hover(function () {
            $(this).children('ul').stop().fadeToggle(400);
        });

        // CounDown JS
        $('.counter').counterUp({
            delay: 10,
            time: 1000
        });

        // Project ISOTOPE JS
        $(".project-filter-menu li").on('click', function () {

            $(".project-filter-menu li").removeClass('active');
            $(this).addClass('active');

            var filterValue = $(this).attr('data-filter');
            $(".project-content-wrap").isotope({
                filter: filterValue,
                stagger: 100
            });
        });

        // Testimonial Carousel JS
        $(".testimonial-content").owlCarousel({
            items: 1,
            loop: true,
            autoplay: true,
            autoplayTimeout: 1000,
            autoplaySpeed: 2000
        });

        // Partner Carousel JS
        $(".partner-content-wrap").owlCarousel({
            items: 4,
            loop: true,
            rtl: true,
            autoplay: true,
            autoplayTimeout: 1000,
            autoplaySpeed: 2000,
            responsive: {
                0: {
                    items: 1
                },
                350: {
                    items: 2
                },
                576: {
                    items: 3
                },
                992: {
                    items: 4
                }
            }
        });

        // SlickNav Responsive menu
        $('.mainmenu').slicknav({
            label: '',
            duration: 400,
            prependTo: '.preheader-area .container'
        });

        // Home2 Doing Think Carousel
        $(".right-think-wrap").owlCarousel({
            items: 3,
            loop: true,
            autoplay: true,
            margin: 30,
            autoplayTimeout: 2000,
            autoplaySpeed: 2000,
            responsive: {
                0: {
                    items: 1
                },
                480: {
                    items: 2
                },
                768: {
                    items: 3
                }
            }
        });

        // Nice Select
        $('select').niceSelect();

        // Home 3 Business Plan
        $('.business-plan-wrap').owlCarousel({
            autoplay: true,
            center: true,
            items: 3,
            loop: true,
            autoplayTimeout: 3000,
            smartSpeed: 2000,
            responsive: {
                0: {
                    items: 1
                },
                576: {
                    items: 1
                },
                768: {
                    items: 2
                },
                992: {
                    items: 3
                }
            }
        });

    }); //Ready Function End

    jQuery(window).on('load', function () {
        jQuery(".project-content-wrap").isotope();
        jQuery('#preloader').delay(1000).fadeOut('slow', function() { $(this).remove(); });
    }); //window load End


}(jQuery));
