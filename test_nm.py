import app.network_monitor as network_monitor
from app.network_monitor import DatabaseConnection
from app.config import DB_CONFIG
from unittest import mock

def test_start_api():
    assert network_monitor.start_api() is not None
    
def test_terminate_api():
    assert network_monitor.terminate_api() is not None

def test_database_connection_establishes():
    with mock.patch('pymysql.connect') as mock_connect:
        mock_cursor = mock.Mock()
        mock_connect.return_value.cursor.return_value = mock_cursor
        
        with DatabaseConnection() as cursor:
            mock_connect.assert_called_once_with(
                host=DB_CONFIG['host'],
                user=DB_CONFIG['user'],
                password=DB_CONFIG['password'],
                database=DB_CONFIG['database'],
                charset='utf8mb4'
            )
            assert cursor == mock_cursor

def test_database_connection_closes():
    with mock.patch('pymysql.connect') as mock_connect:
        mock_connection = mock.Mock()
        mock_cursor = mock.Mock()
        mock_connection.cursor.return_value = mock_cursor
        mock_connect.return_value = mock_connection
        
        with DatabaseConnection() as cursor:
            pass

        mock_cursor.close.assert_called_once()
        mock_connection.close.assert_called_once()

def test_scan_network():
    assert network_monitor.scan_network("127.0.0.1","22,80,443") is not None
