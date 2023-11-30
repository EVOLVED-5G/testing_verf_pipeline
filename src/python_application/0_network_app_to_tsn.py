import redis
import os
import datetime

from evolved5g.sdk import LocationSubscriber, QosAwareness, ConnectionMonitor, TSNManager

# Get environment variables
REDIS_HOST = os.getenv('REDIS_HOST')
REDIS_PORT = os.environ.get('REDIS_PORT')
tsn_host = os.getenv('TSN_IP')
tsn_port = os.environ.get('TSN_PORT')
capif_host = os.getenv('CAPIF_HOSTNAME')
capif_https_port = os.environ.get('CAPIF_PORT_HTTPS')
folder_path_for_certificates_and_capif_api_key = os.environ.get('PATH_TO_CERTS')

network_app_ids_tokens = (
    {}
)  # Stores the clearance token of each profile application to a Network Application
network_app_name = "MyNetworkApp1"  # The name of our Network Application


def initialize_tsn():
    tsn_manager = TSNManager(  # Initialization of the TNSManager
        folder_path_for_certificates_and_capif_api_key=folder_path_for_certificates_and_capif_api_key,
        capif_host=capif_host,
        capif_https_port=capif_https_port,
        https=False,
        tsn_host=tsn_host,
        tsn_port=tsn_port
    )

    return tsn_manager


def get_profiles():

    tsn = initialize_tsn()
    return tsn.get_tsn_profiles()


def apply_tsn_profile():
    """
    Demonstrates how to apply a TSN profile configuration to a Network Application
    """
    tsn = initialize_tsn()
    profiles = tsn.get_tsn_profiles()
    # For demonstration purposes,  let's select the last profile to apply,
    profile_to_apply = profiles[-1]
    profile_configuration = profile_to_apply.get_configuration_for_tsn_profile()
    # Let's create an TSN identifier for this Net App.
    # This tsn_network_app_identifier can be used in two scenarios
    # a) When you want to apply a profile configuration for your net app
    # b) When you want to clear a profile configuration for your net app
    tsn_network_app_identifier = tsn.TSNNetappIdentifier(netapp_name=network_app_name)

    print(
        f"Generated TSN traffic identifier for Network Application: {tsn_network_app_identifier.value}"
    )
    print(
        f"Apply {profile_to_apply.name} with configuration parameters"
        f"{profile_configuration.get_profile_configuration_parameters()} to Network Application {network_app_name} "
    )
    clearance_token = tsn.apply_tsn_profile_to_netapp(
        profile=profile_to_apply, tsn_netapp_identifier=tsn_network_app_identifier
    )
    print(
        f"The profile configuration has been applied to the network_app. The returned token {clearance_token} can be used "
        f"to reset the configuration"
    )

    return tsn_network_app_identifier,clearance_token


def clear_profile_configuration(tsn_network_app_identifier, clearance_token):
    """
    Demonstrates how to clear a previously applied TSN profile configuration from a Network Application
    """
    tsn = initialize_tsn()
    tsn.clear_profile_for_tsn_netapp_identifier(tsn_network_app_identifier,clearance_token)
    print(f"Cleared TSN configuration from {network_app_name}")


if __name__ == '__main__':

    r = redis.Redis(
        host=REDIS_HOST,
        port=REDIS_PORT,
        decode_responses=True,
    )

    tsn_network_app_id = None
    clear_token = None
    profile_conf = None

    try:
        ans = input("Do you want to test TSN API get_profiles? (Y/n) ")
        if ans == "Y" or ans == 'y':
            profiles = get_profiles()
            print(f"Found {len(profiles)} profiles")
            for profile in profiles:
                profile_configuration = profile.get_configuration_for_tsn_profile()

                print(
                    f"Profile {profile.name} with configuration parameters {profile_configuration.get_profile_configuration_parameters()}")
    except Exception as e:
        status_code = e.args[0]
        print(e)

    try:
        ans = input("Do you want to apply TSN profile to network application? (Y/n) ")
        if ans == "Y" or ans == 'y':
            # When we apply a profile we get back an identifier and a clearance token.
            (tsn_network_app_id, clear_token) = apply_tsn_profile()
    except Exception as e:
        status_code = e.args[0]
        print(e)

    print(tsn_network_app_id)
    print(clear_token)

    try:
        ans = input("Do you want to clear TSN profile? (Y/n) ")
        if ans == "Y" or ans == 'y':
            # These can be used to clear the existing configuration
            clear_profile_configuration(tsn_network_app_id, clear_token)
    except Exception as e:
        status_code = e.args[0]
        print(e)
