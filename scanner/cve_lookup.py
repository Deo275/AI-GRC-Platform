import requests
from packaging.version import Version, InvalidVersion


NVD_CPE_API = "https://services.nvd.nist.gov/rest/json/cpes/2.0"
NVD_CVE_API = "https://services.nvd.nist.gov/rest/json/cves/2.0"


def find_cpes(keyword):
    if keyword and "postgresql" in keyword.lower():
        keyword = "postgresql postgresql"

    params = {
        "keywordSearch": keyword,
        "resultsPerPage": 20
    }

    response = requests.get(
        NVD_CPE_API,
        params=params,
        timeout=30
    )

    response.raise_for_status()

    data = response.json()

    cpes = []

    for item in data.get("products", []):

        cpe = item.get("cpe", {})
        cpe_name = cpe.get("cpeName")

        if cpe_name:
            cpes.append(cpe_name)

    return cpes


def lookup_cves(cpe_name):
    url = "https://services.nvd.nist.gov/rest/json/cves/2.0"

    params = {
        "cpeName": cpe_name,
        "resultsPerPage": 100
    }

    response = requests.get(
        url,
        params=params,
        timeout=30
    )

    response.raise_for_status()

    data = response.json()

    return data.get("vulnerabilities", [])


def get_cvss(cve):

    metrics = cve.get("metrics", {})

    # Prefer modern CVSS versions
    for metric_name in [
        "cvssMetricV40",
        "cvssMetricV31",
        "cvssMetricV30",
    ]:

        metric_list = metrics.get(metric_name)

        if metric_list:

            cvss = metric_list[0].get(
                "cvssData",
                {}
            )

            return {
                "score": cvss.get("baseScore"),
                "severity": cvss.get(
                    "baseSeverity"
                ),
                "version": metric_name
            }

    # Fall back to CVSS v2 for older CVEs
    metric_list = metrics.get("cvssMetricV2")

    if metric_list:

        cvss = metric_list[0].get(
            "cvssData",
            {}
        )

        score = cvss.get("baseScore")

        return {
            "score": score,
            "severity": cvss_v2_severity(score),
            "version": "cvssMetricV2"
        }

    return {
        "score": None,
        "severity": None,
        "version": None
    }


def cvss_v2_severity(score):

    if score is None:
        return None

    if score < 4.0:
        return "Low"

    if score < 7.0:
        return "Medium"

    return "High"


def get_description(cve):

    for description in cve.get(
        "descriptions",
        []
    ):

        if description.get("lang") == "en":
            return description.get("value")

    return None


def extract_version_ranges(configurations):

    ranges = []

    def process_node(node):

        for match in node.get(
            "cpeMatch",
            []
        ):

            criteria = match.get(
                "criteria"
            )

            start_including = match.get(
                "versionStartIncluding"
            )

            start_excluding = match.get(
                "versionStartExcluding"
            )

            end_including = match.get(
                "versionEndIncluding"
            )

            end_excluding = match.get(
                "versionEndExcluding"
            )

            if any([
                start_including,
                start_excluding,
                end_including,
                end_excluding
            ]):

                ranges.append({
                    "criteria": criteria,
                    "start_including":
                        start_including,
                    "start_excluding":
                        start_excluding,
                    "end_including":
                        end_including,
                    "end_excluding":
                        end_excluding
                })

        for child in node.get(
            "children",
            []
        ):

            process_node(child)

    for configuration in configurations:

        for node in configuration.get(
            "nodes",
            []
        ):

            process_node(node)

    return ranges

def version_matches_range(
    installed_version,
    version_range
):

    try:
        version = Version(installed_version)

    except InvalidVersion:
        return False

    start_including = version_range.get(
        "start_including"
    )

    start_excluding = version_range.get(
        "start_excluding"
    )

    end_including = version_range.get(
        "end_including"
    )

    end_excluding = version_range.get(
        "end_excluding"
    )

    try:

        if start_including:
            if version < Version(start_including):
                return False

        if start_excluding:
            if version <= Version(start_excluding):
                return False

        if end_including:
            if version > Version(end_including):
                return False

        if end_excluding:
            if version >= Version(end_excluding):
                return False

    except InvalidVersion:
        return False

    return True


def criteria_matches_product(criteria, product_cpe):

    if not criteria:
        return False

    if not product_cpe:
        return False

    criteria_parts = criteria.split(":")

    product_parts = product_cpe.split(":")

    if len(criteria_parts) < 5:
        return False

    if len(product_parts) < 5:
        return False

    # Compare CPE type
    if criteria_parts[2] != product_parts[2]:
        return False

    # Compare vendor
    if (
        criteria_parts[3] != "*"
        and criteria_parts[3]
        != product_parts[3]
    ):
        return False

    # Compare product
    if (
        criteria_parts[4] != "*"
        and criteria_parts[4]
        != product_parts[4]
    ):
        return False

    return True


def evaluate_cve_configuration(
    node,
    product_cpe,
    installed_version
):

    operator = node.get(
        "operator",
        "OR"
    ).upper()

    negate = node.get(
        "negate",
        False
    )

    results = []

    # Evaluate direct CPE matches
    for match in node.get(
        "cpeMatch",
        []
    ):

        criteria = match.get(
            "criteria"
        )

        vulnerable = match.get(
            "vulnerable",
            True
        )

        if not criteria_matches_product(
            criteria,
            product_cpe
        ):
            results.append(False)
            continue

        if not vulnerable:
            results.append(False)
            continue

        version_range = {
            "start_including":
                match.get(
                    "versionStartIncluding"
                ),

            "start_excluding":
                match.get(
                    "versionStartExcluding"
                ),

            "end_including":
                match.get(
                    "versionEndIncluding"
                ),

            "end_excluding":
                match.get(
                    "versionEndExcluding"
                )
        }

        has_range = any(
            version_range.values()
        )

        if not has_range:

            results.append(True)

        else:

            results.append(
                version_matches_range(
                    installed_version,
                    version_range
                )
            )

    # Evaluate child nodes
    for child in node.get(
        "children",
        []
    ):

        results.append(
            evaluate_cve_configuration(
                child,
                product_cpe,
                installed_version
            )
        )

    # Remove impossible/unknown values
    known_results = [
        result
        for result in results
        if result is not None
    ]

    has_unknown = any(
        result is None
        for result in results
    )

    if operator == "AND":

        if any(
            result is False
            for result in known_results
        ):
            final_result = False

        elif has_unknown:
            final_result = None

        else:
            final_result = True

    else:

        if any(
            result is True
            for result in known_results
        ):
            final_result = True

        elif has_unknown:
            final_result = None

        else:
            final_result = False

    if negate:
        if final_result is True:
            return False

        if final_result is False:
            return True

        return None

    return final_result


def determine_cve_confidence(
    installed_version,
    configurations,
    product_cpe
):

    if not product_cpe:
        return "Unknown"

    if not configurations:
        return "Unknown"

    results = []

    for configuration in configurations:

        for node in configuration.get(
            "nodes",
            []
        ):

            result = evaluate_cve_configuration(
                node,
                product_cpe,
                installed_version
            )

            results.append(result)

    if any(
        result is True
        for result in results
    ):
        return "Confirmed"

    if any(
        result is None
        for result in results
    ):
        return "Unknown"

    return "Not Applicable"

def get_cve_information(
    cpe_name,
    installed_version=None
):

    data = lookup_cves(cpe_name)

    results = []

    for item in data:

        cve = item.get(
            "cve",
            {}
        )

        cvss = get_cvss(cve)

        configurations = cve.get(
            "configurations",
            []
        )

        confidence = determine_cve_confidence(
            installed_version,
            configurations,
            cpe_name
        )

        ranges = extract_version_ranges(
            configurations
        )

        results.append({

            "cve":
                cve.get("id"),

            "description":
                get_description(cve),

            "cvss_score":
                cvss["score"],

            "severity":
                cvss["severity"],

            "cvss_version":
                cvss["version"],

            "published":
                cve.get("published"),

            "last_modified":
                cve.get(
                    "lastModified"
                ),

            "version_ranges":
                ranges,

            "confidence":
                confidence

        })

    return results


if __name__ == "__main__":

    print(
        "Searching NVD for PostgreSQL..."
    )

    cpes = find_cpes("PostgreSQL")

    print(
        f"CPEs found: {len(cpes)}"
    )

    generic_cpe = (
        "cpe:2.3:a:postgresql:postgresql:"
        "-:*:*:*:*:*:*:*"
    )

    if generic_cpe not in cpes:

        print(
            "\nGeneric PostgreSQL CPE "
            "was not found."
        )

        exit()

    print(
        "\nUsing CPE:"
    )

    print(generic_cpe)

    results = get_cve_information(
        generic_cpe,
        installed_version=None
    )

    print(
        f"\nCVE records returned: "
        f"{len(results)}"
    )

    for result in results[:10]:

        print("\n-------------------------")

        print(
            "CVE:",
            result["cve"]
        )

        print(
            "CVSS:",
            result["cvss_score"]
        )

        print(
            "Severity:",
            result["severity"]
        )

        print(
            "CVSS Version:",
            result["cvss_version"]
        )

        print(
            "Confidence:",
            result["confidence"]
        )

        print(
            "Version ranges:"
        )

        if result["version_ranges"]:

            for version_range in result[
                "version_ranges"
            ]:

                print(
                    version_range
                )

        else:

            print(
                "No explicit version range"
            )