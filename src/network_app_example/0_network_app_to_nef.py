import redis
import os
import datetime

from evolved5g.sdk import LocationSubscriber, QosAwareness, ConnectionMonitor
from evolved5g.swagger_client import UsageThreshold, Configuration, ApiClient, LoginApi
from evolved5g.swagger_client.rest import ApiException

# Get environment variables
REDIS_HOST = os.getenv('REDIS_HOST')
REDIS_PORT = os.environ.get('REDIS_PORT')


def request_nef_token(nef_host, username, password):
    configuration = Configuration()
    configuration.host = nef_host
    configuration.verify_ssl = False
    api_client = ApiClient(configuration=configuration)
    api_client.select_header_content_type(["application/x-www-form-urlencoded"])
    api = LoginApi(api_client)
    token = api.login_access_token_api_v1_login_access_token_post("", username, password, "", "", "")

    return token


def read_and_delete_all_existing_qos_subscriptions(host, nef_token, certificate_folder, capifhost, capifport):
    # How to get all subscriptions
    network_app_id = "myNetworkApp"
    qos_awareness = QosAwareness(host, nef_token, certificate_folder, capifhost, capifport)

    try:
        all_subscriptions = qos_awareness.get_all_subscriptions(network_app_id)
        print(all_subscriptions)

        for subscription in all_subscriptions:
            id = subscription.link.split("/")[-1]
            print("Deleting subscription with id: " + id)
            qos_awareness.delete_subscription(network_app_id, id)
    except ApiException as ex:
        if ex.status == 404:
            print("No active transcriptions found")
        else: #something else happened, re-throw the exception
            raise


def read_and_delete_all_existing_location_subscriptions(host, nef_token, certificate_folder, capifhost, capifport):
    # How to get all subscriptions
    network_app_id = "myNetworkApp"
    location_subscriber = LocationSubscriber(host, nef_token, certificate_folder, capifhost, capifport)

    try:
        all_subscriptions = location_subscriber.get_all_subscriptions(network_app_id, 0, 100)

        print(all_subscriptions)

        for subscription in all_subscriptions:
            id = subscription.link.split("/")[-1]
            print("Deleting subscription with id: " + id)
            location_subscriber.delete_subscription(network_app_id, id)
    except ApiException as ex:
        if ex.status == 404:
            print("No active transcriptions found")
        else: #something else happened, re-throw the exception
            raise


def monitor_subscription(num_of_reports, host, nef_token, certificate_folder, capifhost, capifport, callback_server):
    expire_time = (datetime.datetime.today() + datetime.timedelta(days=1)).strftime('%Y-%m-%dT%H:%M:%SZ')
    network_app_id = "myNetworkApp"
    location_subscriber = LocationSubscriber(host, nef_token, certificate_folder, capifhost, capifport)
    external_id = "10001@domain.com"
    print(nef_token)

    subscription = location_subscriber.create_subscription(
        netapp_id=network_app_id,
        external_id=external_id,
        notification_destination=callback_server,
        maximum_number_of_reports=num_of_reports,
        monitor_expire_time=expire_time
    )
    monitoring_response = subscription.to_dict()

    return monitoring_response


def connection_monitoring_ue_reachability(host, nef_token, certificate_folder, capifhost, capifport, callback_server):
    expire_time = (datetime.datetime.utcnow() + datetime.timedelta(days=1)).isoformat() + "Z"
    network_app_id = "myNetworkApp"
    connection_monitor = ConnectionMonitor(host, nef_token, certificate_folder, capifhost, capifport)
    external_id = "10001@domain.com"

    subscription_when_not_connected = connection_monitor.create_subscription(
        netapp_id=network_app_id,
        external_id=external_id,
        notification_destination=callback_server,
        monitoring_type=ConnectionMonitor.MonitoringType.INFORM_WHEN_CONNECTED,
        wait_time_before_sending_notification_in_seconds=5,
        maximum_number_of_reports=1000,
        monitor_expire_time=expire_time
    )
    connection_monitoring_response = subscription_when_not_connected.to_dict()

    return connection_monitoring_response


def connection_monitoring_loss_of_conn(host, nef_token, certificate_folder, capifhost, capifport, callback_server):
    expire_time = (datetime.datetime.utcnow() + datetime.timedelta(days=1)).isoformat() + "Z"
    network_app_id = "myNetworkApp"
    connection_monitor = ConnectionMonitor(host, nef_token, certificate_folder, capifhost, capifport)
    external_id = "10001@domain.com"

    subscription_when_not_connected = connection_monitor.create_subscription(
        netapp_id=network_app_id,
        external_id=external_id,
        notification_destination=callback_server,
        monitoring_type=ConnectionMonitor.MonitoringType.INFORM_WHEN_NOT_CONNECTED,
        wait_time_before_sending_notification_in_seconds=5,
        maximum_number_of_reports=1000,
        monitor_expire_time=expire_time
    )
    connection_monitoring_response = subscription_when_not_connected.to_dict()

    return connection_monitoring_response


def sessionqos_subscription(host, nef_token, certificate_folder, capifhost, capifport, callback_server):
    network_app_id = "myNetworkApp"
    qos_awereness = QosAwareness(host, nef_token, certificate_folder, capifhost, capifport)
    equipment_network_identifier = "10.0.0.1"
    network_identifier = QosAwareness.NetworkIdentifier.IP_V4_ADDRESS
    conversational_voice = QosAwareness.GBRQosReference.CONVERSATIONAL_VOICE
    # In this scenario we monitor UPLINK
    uplink = QosAwareness.QosMonitoringParameter.UPLINK
    # Minimum delay of data package during uplink, in milliseconds
    uplink_threshold = 20
    gigabyte = 1024 * 1024 * 1024
    # Up to 10 gigabytes 5 GB downlink, 5gb uplink
    usage_threshold = UsageThreshold(duration=None,  # not supported
                                     total_volume=10 * gigabyte,  # 10 Gigabytes of total volume
                                     downlink_volume=5 * gigabyte,  # 5 Gigabytes for downlink
                                     uplink_volume=5 * gigabyte  # 5 Gigabytes for uplink
                                     )

    subscription = qos_awereness.create_guaranteed_bit_rate_subscription(
        netapp_id=network_app_id,
        equipment_network_identifier=equipment_network_identifier,
        network_identifier=network_identifier,
        notification_destination=callback_server,
        gbr_qos_reference=conversational_voice,
        usage_threshold=usage_threshold,
        qos_monitoring_parameter=uplink,
        threshold=uplink_threshold,
        reporting_mode=QosAwareness.EventTriggeredReportingConfiguration(wait_time_in_seconds=10)
    )

    qos_awereness_response = subscription.to_dict()

    return qos_awereness_response


if __name__ == '__main__':

    r = redis.Redis(
        host=REDIS_HOST,
        port=REDIS_PORT,
        decode_responses=True,
    )

    nef_url = "https://{}:{}".format(os.getenv('NEF_IP'), os.environ.get('NEF_PORT'))
    nef_callback = "http://{}:{}/nefcallbacks".format(os.getenv('NEF_CALLBACK_IP'), os.environ.get('NEF_CALLBACK_PORT'))
    nef_user = os.getenv('NEF_USER')
    nef_pass = os.environ.get('NEF_PASS')
    capif_host = os.getenv('CAPIF_HOSTNAME')
    capif_https_port = os.environ.get('CAPIF_PORT_HTTPS')
    folder_path_for_certificates_and_capif_api_key = os.environ.get('PATH_TO_CERTS')

    # Get NEF-created token
    try:
        if not r.exists('nef_access_token'):
            token = request_nef_token(nef_url, nef_user, nef_pass)
            r.set('nef_access_token', token.access_token)
            print("NEF Token: {}\n".format(token.access_token))
    except Exception as e:
        status_code = e.args[1]
        print(e)

    # Create a Location Reporting subscription
    try:
        nef_access_token = r.get('nef_access_token')
        ans = input("Do you want to test Monitoring Event API? (Y/n) ")
        if ans == "Y" or ans == 'y':
            times = input("Number of location monitoring callbacks: ")
            last_response_from_nef = monitor_subscription(int(times),
                                                          nef_url,
                                                          nef_access_token,
                                                          folder_path_for_certificates_and_capif_api_key,
                                                          capif_host, capif_https_port, nef_callback)
            r.set('last_response_from_nef', str(last_response_from_nef))
            print("{}\n".format(last_response_from_nef))
    except Exception as e:
        status_code = e.args[1]
        print(e)

    # Create a Loss of Connectivity subscription
    try:
        nef_access_token = r.get('nef_access_token')
        ans = input("Do you want to test Connection Monitoring API (LOSS_OF_CONNECTIVITY)? (Y/n) ")
        if ans == "Y" or ans == 'y':
            last_response_from_nef = connection_monitoring_loss_of_conn(nef_url,
                                                                        nef_access_token,
                                                                        folder_path_for_certificates_and_capif_api_key,
                                                                        capif_host,
                                                                        capif_https_port,
                                                                        nef_callback)
            r.set('last_response_from_nef', str(last_response_from_nef))
            print("{}\n".format(last_response_from_nef))

    except Exception as e:
        status_code = e.args[1]
        print(e)

    # Create a UE Reachability subscription
    try:
        nef_access_token = r.get('nef_access_token')
        ans = input("Do you want to test Connection Monitoring API (UE_REACHABILITY)? (Y/n) ")
        if ans == "Y" or ans == 'y':
            last_response_from_nef = connection_monitoring_ue_reachability(nef_url,
                                                                           nef_access_token,
                                                                           folder_path_for_certificates_and_capif_api_key,
                                                                           capif_host,
                                                                           capif_https_port,
                                                                           nef_callback)
            r.set('last_response_from_nef', str(last_response_from_nef))
            print("{}\n".format(last_response_from_nef))
    except Exception as e:
        status_code = e.args[1]
        print(e)

    # Create a QoS subscription
    try:
        nef_access_token = r.get('nef_access_token')
        ans = input("Do you want to test Session-with-QoS API? (Y/n) ")
        if ans == "Y" or ans == 'y':
            last_response_from_nef = sessionqos_subscription(nef_url,
                                                             nef_access_token,
                                                             folder_path_for_certificates_and_capif_api_key,
                                                             capif_host,
                                                             capif_https_port,
                                                             nef_callback)
            r.set('last_response_from_nef', str(last_response_from_nef))
            print("{}\n".format(last_response_from_nef))
    except Exception as e:
        status_code = e.args[1]
        print(e)

    # Delete all Location-aware subscriptions (e.g. LOCATION_REPORTING, UE_REACHABILITY, LOSS_OF_CONNECTIVITY)
    try:
        nef_access_token = r.get('nef_access_token')
        ans = input("Do you want to delete all existing Location subscriptions (LOCATION_REPORTING, UE_REACHABILITY, LOSS_OF_CONNECTIVITY)? (Y/n) ")
        if ans == "Y" or ans == 'y':
            last_response_from_nef = read_and_delete_all_existing_location_subscriptions(nef_url,
                                                                                         nef_access_token,
                                                                                         folder_path_for_certificates_and_capif_api_key,
                                                                                         capif_host,
                                                                                         capif_https_port)
    except Exception as e:
        status_code = e.args[1]
        print(e)

    # Delete all QoS-aware subscriptions
    try:
        nef_access_token = r.get('nef_access_token')
        ans = input("Do you want to delete all existing QoS subscriptions? (Y/n) ")
        if ans == "Y" or ans == 'y':
            last_response_from_nef = read_and_delete_all_existing_qos_subscriptions(nef_url,
                                                                                    nef_access_token,
                                                                                    folder_path_for_certificates_and_capif_api_key,
                                                                                    capif_host,
                                                                                    capif_https_port)
    except Exception as e:
        status_code = e.args[1]
        print(e)