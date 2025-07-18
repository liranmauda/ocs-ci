import datetime
import logging

import boto3

from ocs_ci.ocs import constants
from ocs_ci.ocs.bucket_utils import retrieve_verification_mode
from ocs_ci.utility import version

logger = logging.getLogger(__name__)


class HttpResponseParser(object):
    """
    A simple class for parsing HTTP responses
    """

    def __init__(self, http_response):
        """
        Initializer function

        Args:
            http_response (dict): HTTP response
        """
        logger.info("http response:\n%s" % http_response)

        self.metadata = http_response["ResponseMetadata"]
        logger.info(f"metadata: {self.metadata}")

        self.headers = self.metadata["HTTPHeaders"]
        logger.info(f"headers: {self.headers}")

        self.status_code = self.metadata["HTTPStatusCode"]
        logger.info(f"status code: {self.status_code}")

        self.error = http_response.get("Error", None)
        logger.info(f"Error: {self.error}")


class NoobaaAccount(object):
    """
    Class for Noobaa account
    """

    (
        s3_resource,
        s3_endpoint,
        account_name,
        email_id,
        token,
        access_key_id,
        access_key,
    ) = (None,) * 7

    def __init__(
        self,
        mcg,
        name,
        email,
        allow_bucket_creation=True,
        buckets=None,
        admin_access=False,
        s3_access=True,
        full_bucket_access=True,
        backingstore_name=constants.DEFAULT_NOOBAA_BACKINGSTORE,
    ):
        """
        Initializer function

        Args:
            mcg (obj): Multi cloud gateway object
            name (str): Name of noobaa account
            email (str): Email id to be assigned to noobaa account
            buckets (list): list of bucket names to be given permission
            admin_access (bool): True for admin privilege, otherwise False. Default (False)
            s3_access (bool): True for S3 access, otherwise False. Default (True)
            backingstore_name (str): Backingstore name on which buckets created
                using this account to be placed by default. Default("noobaa-default-backing-store")
            full_bucket_access (bool): True for future bucket access, otherwise False. Default (False)
        """
        self.account_name = name
        self.email_id = email
        self.mcg = mcg
        if buckets:
            params_dict = {
                "email": email,
                "name": name,
                "has_login": admin_access,
                "s3_access": s3_access,
                "default_pool": backingstore_name,
                "allowed_buckets": {
                    "full_permission": full_bucket_access,
                    "permission_list": buckets,
                },
            }
        else:
            params_dict = {
                "email": email,
                "name": name,
                "has_login": admin_access,
                "s3_access": s3_access,
                "default_pool": backingstore_name,
            }

        if not allow_bucket_creation:
            params_dict["allow_bucket_creation"] = allow_bucket_creation
        (
            params_dict
            if (version.get_semantic_ocs_version_from_config() < version.VERSION_4_9)
            else params_dict.pop("default_pool")
        )
        response = mcg.send_rpc_query(
            api="account_api", method="create_account", params=params_dict
        ).json()
        self.access_key_id = response["reply"]["access_keys"][0]["access_key"]
        self.access_key = response["reply"]["access_keys"][0]["secret_key"]
        self.s3_endpoint = mcg.s3_endpoint
        self.token = response["reply"]["token"]

        self.s3_resource = boto3.resource(
            "s3",
            verify=retrieve_verification_mode(),
            endpoint_url=self.s3_endpoint,
            aws_access_key_id=self.access_key_id,
            aws_secret_access_key=self.access_key,
        )

        self.s3_client = boto3.client(
            "s3",
            verify=retrieve_verification_mode(),
            endpoint_url=self.s3_endpoint,
            aws_access_key_id=self.access_key_id,
            aws_secret_access_key=self.access_key,
        )

    def delete_account(self):
        """
        Delete the noobaa account

        Returns:
            Response for noobaa `delete_account` api call

        """
        params_dict = {"email": self.email_id}
        return self.mcg.send_rpc_query(
            api="account_api", method="delete_account", params=params_dict
        )

    def update_account_email(self, new_email):
        """
        Update the noobaa account with new email

        Returns:
            Response for noobaa 'update_account' api call

        """
        params_dict = {"email": self.email_id, "new_email": new_email}
        update_acc = self.mcg.send_rpc_query(
            api="account_api", method="update_account", params=params_dict
        )
        self.email_id = new_email
        return update_acc


def gen_bucket_policy(
    user_list,
    actions_list,
    resources_list,
    effect=None,
    sid="statement",
    principal_property=None,
    action_property=None,
    resource_property=None,
):
    """
    Function prepares bucket policy parameters in syntax and format provided by AWS bucket policy

    Args:
        user_list (list): List of user accounts to access bucket policy
        actions_list (list): List of actions in bucket policy eg: Get, Put objects etc
        resources_list (list): List of resources. Eg: Bucket name, specific object in a bucket etc
        effect (str): Permission given to the bucket policy ie: Allow(default) or Deny
        sid (str): Statement name. Can be any string. Default: "Statement"
        principal_property (str): Element to specify the principal to allow/deny access to a resource.
        action_property (str): Element describes the specific action(s) that will be allowed or denied.
        resource_property (str):  Element specifies the object(s) that the statement covers

    Returns:
        dict: Bucket policy in json format
    """
    principals = user_list
    actions = list(map(lambda action: "s3:%s" % action, actions_list))
    resources = list(
        map(lambda bucket_name: "arn:aws:s3:::%s" % bucket_name, resources_list)
    )
    ver = datetime.date.today().strftime("%Y-%m-%d")

    principal = principal_property if principal_property else "Principal"
    effect = effect if effect else "Allow"
    action = action_property if action_property else "Action"
    resource = resource_property if resource_property else "Resource"

    logger.info(f"version: {ver}")
    logger.info(f"{principal}: {principals}")
    logger.info(f"{action}: {actions_list}")
    logger.info(f"{resource}: {resources_list}")
    logger.info(f"effect: {effect}")
    logger.info(f"sid: {sid}")
    bucket_policy = {
        "Version": ver,
        "Statement": [
            {
                action: actions,
                principal: {"AWS": principals},
                resource: resources,
                "Effect": effect,
                "Sid": sid,
            }
        ],
    }

    logger.info(f"bucket_policy: {bucket_policy}")
    return bucket_policy
