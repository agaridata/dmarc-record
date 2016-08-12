class DMARCPolicy < ClassyEnum::Base
  def display_name
    text
  end
end

class DMARCPolicy::None < DMARCPolicy
  def text
    N_("Monitor")
  end

  def policy_code
    "n"
  end
end

class DMARCPolicy::Quarantine < DMARCPolicy
  def text
    N_("Quarantine")
  end

  def policy_code
    "q"
  end
end

class DMARCPolicy::Reject < DMARCPolicy
  def text
    N_("Reject")
  end

  def policy_code
    "r"
  end
end
