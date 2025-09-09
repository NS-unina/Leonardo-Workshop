controlFlow(c_01_operator, c_02_radio_control, ca_01_set_control).
controlFlow(c_02_radio_control, c_01_operator, fb_01_send_feedback).
controlFlow(c_02_radio_control, c_03_autopilot, ca_02_flight_commands_radio).
controlFlow(c_03_autopilot, c_02_radio_control, fb_02_drone_status_radio).
controlFlow(c_06_gnss_source, c_05_geolocation_system, fb_03_gps_position_nmea0183).
controlFlow(c_05_geolocation_system, c_03_autopilot, ca_03_drone_position_bus).
controlFlow(c_07_physical_process, c_08_imu, fb_04_acceleration).
controlFlow(c_08_imu, c_03_autopilot, fb_05_acceleration_data_bus).
controlFlow(c_07_physical_process, c_12_pressure_sensor, fb_06_pressure).
controlFlow(c_07_physical_process, c_13_electronic_compass, fb_07_angular_velocity).
controlFlow(c_09_battery, c_03_autopilot, fb_08_battery_status_bus).
controlFlow(c_12_pressure_sensor, c_03_autopilot, fb_10_pressure_data_bus).
controlFlow(c_13_electronic_compass, c_03_autopilot, fb_11_angular_velocity_data_bus).
controlFlow(c_04_camera, c_02_radio_control, fb_09_image_transmission).
controlFlow(c_03_autopilot, c_10_esc, ca_04_motor_velocity_voltage).
controlFlow(c_10_esc, c_11_motors, ca_05_motor_velocity_voltage).
controlFlow(c_11_motors, c_07_physical_process, ca_06_acceleration).
physicalLayer(nmea0183, c_05_geolocation_system, c_06_gnss_source, physical).
weaknessPhysicalLayer(ac7, nmea0183, coverzone).
attackGoal(canspoof(fb_03_gps_position_nmea0183)).
