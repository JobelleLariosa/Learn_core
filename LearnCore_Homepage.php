<?php
session_start();
if (!isset($_SESSION['user_data'])) {
    header("Location: LearnCore_Login_V2.html");
    exit;
}

$user = $_SESSION['user_data'];
?>

<!DOCTYPE html>
<html lang="en">
<head>
    <title>LearnCore</title>
    <meta charset="utf-8">
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <link href="css/bootstrap.min.css" rel="stylesheet">

    <!-- font awesome cdn link -->
    <link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.2.0/css/all.min.css">

    <!-- google font cdn link -->
    <link rel="preconnect" href="https://fonts.googleapis.com">
    <link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
    <link href="https://fonts.googleapis.com/css2?family=Rokkitt&display=swap" rel="stylesheet">

    <!-- import jquery and bootstrap-->
    <script src="https://ajax.googleapis.com/ajax/libs/jquery/3.6.0/jquery.min.js"></script> 
    <script src="js/bootstrap.min.js"></script> 
    <link rel="icon" type="image/png" href="img/LearnCore3.png">

    <style>
        .Maincontainer {
            background-image: url(img/backgroundlearn_core.png);
            min-height: 100vh;
            display: flex;
            flex-direction: column;
            align-items: center;
            justify-content: center;
        }

        :root {
            --gradient: linear-gradient(90deg, #806905dc, #d4902a);
        }

        * {
            font-family: 'Rokkitt', serif;
            margin: 0;
            padding: 0;
            box-sizing: border-box;
            border: none;
            text-decoration: none;
            text-transform: capitalize;
            transition: all linear;
        }

        *::selection {
            background: #ebb70c;
            color: #fff12cec;
        }

        html {
            font-size: 62.5%;
            overflow-x: hidden;
        }

        html::-webkit-scrollbar {
            width: 1.5rem;
        }

        html::-webkit-scrollbar-track {
            background: #ebcf32d7;
        }

        html::-webkit-scrollbar-thumb {
            background: linear-gradient(#ffd382e7, #e6b531);
        }

        .wrapper {
            padding: 50px 0;
            text-align: center;
        }

        .card-img-container img {
            width: 100%;
            border-radius: 15px;
        }

        .card-shadow {
            box-shadow: 0px 8px 20px 0px rgb(0 0 0 / 15%);
            border-radius: 1.5rem;
            margin-bottom: 20px;
        }

        .card-text {
            text-align: left;
            font-size: 1.7rem;
        }

        .card-title {
            text-align: left;
            font-size: 2.5rem;
            margin-bottom: 10px;
        }

        .logo {
            border-radius: 100%;
        }

        header {
            width: 100%;
            display: flex;
            align-items: center;
            justify-content: space-between;
            position: fixed;
            top: 0;
            left: 0;
            z-index: 1000;
            padding: 1.5rem 7%;
            background-image: url(img/backgroundlearn_core.png);
            box-shadow: 0 .1rem .3rem rgba(0, 0, 0, .4);
        }

        header .Subjects ul {
            display: flex;
            align-items: center;
            list-style: none;
            font-size: 2rem;
        }

        header .Subjects ul li {
            margin: 0 1rem;
        }

        header .Subjects ul li a {
            font-size: 2.8rem;
            color: #ffffff;
        }

        header .Subjects ul li a:hover {
            color: #0c22eb;
        }

        .mainContainer {
            padding-top: 8rem;
        }

        .quiz-container {
            background: aliceblue;
            box-shadow: 0 0 20px 2px rgb(100, 100, 100, 1.5rem);
            width: 450px;
        }

        .quiz-header {
            padding: 4rem;
        }

        h2 {
            padding: 1rem;
            text-align: center;
            margin: 0;
            font-size: 3.5rem;
        }

        ul {
            list-style-type: none;
            padding: 0;
        }

        ul li {
            font-size: 2.8rem;
            margin: 1rem;
        }

        ul li label {
            cursor: pointer;
        }

        button {
            background: #0c22eb;
            color: #fff;
            border: none;
            display: block;
            width: 50%;
            cursor: pointer;
            font-size: 1.3rem;
            padding: 1.1rem;
            margin: 1rem auto;
        }
    </style>
</head>
<body onload="Addname()">
    <div class="Maincontainer">
        <header>
            <a href="#"><img src="img/LearnCore3.png" width="100" height="100" class="logo"></a>
            <nav class="Subjects">
                <ul>
                    <li><a href="LearnCore_Homepage.html">Home</a></li>
                    <li><a href="AboutUs.html">About</a></li>
                    <li><a href="LearnCore_Login_V2.HTML">Sign Out</a></li>
                </ul>
            </nav>
        </header>
        <div class="mainContainer" id="Home1">
            <div class="container wrapper">
                <div class="row">
                    <div class="col-sm-12">
                        <div class="card card-shadow">
                            <div class="card-body">
                                <h4 class="card-title">
                                    <a href="welcome.html"></a>
                                    <label id="welcomeName" style="font-size: 2.5rem;"><b>Welcome! Enjoy learning in LearnCore!</b></label>
                                </h4>                       
                            </div>
                        </div>
                    </div>
                </div>
                <div class="row" id="main-menu">
                    <div class="col-md-3 col-sm-6">
                        <div class="card card-shadow">
                            <div class="card-img-container">
                                <img src="img/math1.jpg" alt="Mathematics">
                            </div>
                            <div class="card-body">
                                <h4 class="card-title"><b>Mathematics</b></h4>
                                <p class="card-text">Learn about Mathematics</p>
                                <a href="mathematics.html" class="btn btn-primary btn-lg">Start Learning</a>
                            </div>
                        </div>
                    </div>
                    <div class="col-md-3 col-sm-6">
                        <div class="card card-shadow">
                            <div class="card-img-container">
                                <img src="img/science1.png" alt="Science">
                            </div>
                            <div class="card-body">
                                <h4 class="card-title"><b>Science</b></h4>
                                <p class="card-text"> Learn about Science</p>
                                <a href="science_core.html" class="btn btn-primary btn-lg">Start Learning</a>
                            </div>
                        </div>
                    </div>
                    <div class="col-md-3 col-sm-6">
                        <div class="card card-shadow">
                            <div class="card-img-container">
                                <img src="img/english.png" alt="English">
                            </div>
                            <div class="card-body">
                                <h4 class="card-title"><b>English</b></h4>
                                <p class="card-text"> Learn about English</p>
                                <a href="English_core.html" class="btn btn-primary btn-lg">Start Learning</a>
                            </div>
                        </div>
                    </div>
                    <div class="col-md-3 col-sm-6">
                        <div class="card card-shadow">
                            <div class="card-img-container">
                                <img src="img/filipino.png" alt="Filipino">
                            </div>
                            <div class="card-body">
                                <h4 class="card-title"><b>Filipino</b></h4>
                                <p class="card-text">Learn about Filipino</p>
                                <a href="Filipino_Core.html" class="btn btn-primary btn-lg">Start Learning</a>
                            </div>
                        </div>
                    </div>
                </div>
            </div>
        </div>
    </div>
    <script>
        $(document).ready(function(){
            $('#div-addition').hide();
            $('#div-subtraction').hide();
            $('#div-multiplication').hide();
            $('#div-division').hide();
            $('#div-factorial').hide();
            $('#div-Pemdas').hide();
        });
        function Addname() {
            const queryString = window.location.search;
            const urlParams = new URLSearchParams(queryString);
            const userName = urlParams.get('user');
            if (userName) {
                document.getElementById('welcomeName').innerHTML = `<b>Welcome, ${userName}! Enjoy learning in LearnCore!</b>`;
            }
        }
    </script>
</body>
</html>