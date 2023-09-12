-- phpMyAdmin SQL Dump
-- version 5.2.1
-- https://www.phpmyadmin.net/
--
-- Host: localhost:3306
-- Generation Time: Sep 12, 2023 at 07:09 AM
-- Server version: 8.0.30
-- PHP Version: 8.1.10

SET SQL_MODE = "NO_AUTO_VALUE_ON_ZERO";
START TRANSACTION;
SET time_zone = "+00:00";


/*!40101 SET @OLD_CHARACTER_SET_CLIENT=@@CHARACTER_SET_CLIENT */;
/*!40101 SET @OLD_CHARACTER_SET_RESULTS=@@CHARACTER_SET_RESULTS */;
/*!40101 SET @OLD_COLLATION_CONNECTION=@@COLLATION_CONNECTION */;
/*!40101 SET NAMES utf8mb4 */;

--
-- Database: `capstone`
--

-- --------------------------------------------------------

--
-- Table structure for table `devices`
--

CREATE TABLE `devices` (
  `dev_id` int NOT NULL,
  `user_id` int NOT NULL,
  `deviceID` varchar(45) NOT NULL,
  `date_registered` datetime NOT NULL DEFAULT CURRENT_TIMESTAMP
) ENGINE=InnoDB DEFAULT CHARSET=latin1;

--
-- Dumping data for table `devices`
--

INSERT INTO `devices` (`dev_id`, `user_id`, `deviceID`, `date_registered`) VALUES
(11, 2, 'EC336206-18FF-E611-9BD2-FC4596A496C2', '2023-05-31 10:08:59'),
(12, 1, '3CB7BEED-0D51-ED11-80E9-088FC37E955D', '2023-05-31 10:00:05');

-- --------------------------------------------------------

--
-- Table structure for table `users`
--

CREATE TABLE `users` (
  `user_id` int NOT NULL,
  `fname` varchar(20) NOT NULL,
  `mname` varchar(20) NOT NULL,
  `lname` varchar(20) NOT NULL,
  `email` varchar(45) NOT NULL,
  `password` varchar(255) NOT NULL
) ENGINE=InnoDB DEFAULT CHARSET=latin1;

--
-- Dumping data for table `users`
--

INSERT INTO `users` (`user_id`, `fname`, `mname`, `lname`, `email`, `password`) VALUES
(1, 'Jephthah Ruel', 'Gonzales', 'Millan', 'jrmillan23@gmail.com', '$2b$12$IhCbHokw34zIH.BTU4YWSelf71Qxs1GUFNX54.c1tWlg4mpMlC.N2'),
(2, 'Jan', 'Gaas', 'Baguio', 'jbg@gmail.com', '$2b$12$0J.SA6mtmtyE4FutkN3gBeOMm5GGWm2qNlPbyN3WLAL6vREFC6owO');

-- --------------------------------------------------------

--
-- Stand-in structure for view `user_devices`
-- (See below for the actual view)
--
CREATE TABLE `user_devices` (
`deviceID` varchar(45)
,`email` varchar(45)
,`fname` varchar(20)
,`lname` varchar(20)
,`mname` varchar(20)
);

-- --------------------------------------------------------

--
-- Structure for view `user_devices`
--
DROP TABLE IF EXISTS `user_devices`;

CREATE ALGORITHM=UNDEFINED DEFINER=`root`@`localhost` SQL SECURITY DEFINER VIEW `user_devices`  AS SELECT `u`.`fname` AS `fname`, `u`.`mname` AS `mname`, `u`.`lname` AS `lname`, `u`.`email` AS `email`, `d`.`deviceID` AS `deviceID` FROM (`devices` `d` left join `users` `u` on((`u`.`user_id` = `d`.`user_id`))) ;

--
-- Indexes for dumped tables
--

--
-- Indexes for table `devices`
--
ALTER TABLE `devices`
  ADD PRIMARY KEY (`dev_id`),
  ADD KEY `user_id` (`user_id`);

--
-- Indexes for table `users`
--
ALTER TABLE `users`
  ADD PRIMARY KEY (`user_id`);

--
-- AUTO_INCREMENT for dumped tables
--

--
-- AUTO_INCREMENT for table `devices`
--
ALTER TABLE `devices`
  MODIFY `dev_id` int NOT NULL AUTO_INCREMENT, AUTO_INCREMENT=14;

--
-- AUTO_INCREMENT for table `users`
--
ALTER TABLE `users`
  MODIFY `user_id` int NOT NULL AUTO_INCREMENT, AUTO_INCREMENT=5;

--
-- Constraints for dumped tables
--

--
-- Constraints for table `devices`
--
ALTER TABLE `devices`
  ADD CONSTRAINT `FK UserID` FOREIGN KEY (`user_id`) REFERENCES `users` (`user_id`);
COMMIT;

/*!40101 SET CHARACTER_SET_CLIENT=@OLD_CHARACTER_SET_CLIENT */;
/*!40101 SET CHARACTER_SET_RESULTS=@OLD_CHARACTER_SET_RESULTS */;
/*!40101 SET COLLATION_CONNECTION=@OLD_COLLATION_CONNECTION */;
