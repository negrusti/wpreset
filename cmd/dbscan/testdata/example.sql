-- Synthetic data only. The domains and payloads do not belong to a real site.
CREATE TABLE `wp_options` (
  `option_id` bigint unsigned NOT NULL,
  `option_name` varchar(191) NOT NULL,
  `option_value` longtext NOT NULL,
  PRIMARY KEY (`option_id`),
  UNIQUE KEY `option_name` (`option_name`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;
INSERT INTO `wp_options` VALUES
(1,'siteurl','https://example.invalid'),
(1842,'widget_custom_html','<script>eval(atob("YWxlcnQoMSk="));location.href="https://example.invalid/redirect";</script>'),
(1843,'encoded_snippet','PD9waHAgZXZhbChiYXNlNjRfZGVjb2RlKCdZV3hsY25Rb01Taz0nKSk7');

CREATE TABLE `wp_plugin_templates` (
  `name` varchar(191),
  `content` longtext
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;
INSERT INTO `wp_plugin_templates` VALUES
('custom_template','<img src="missing" onerror="alert(1)">');
